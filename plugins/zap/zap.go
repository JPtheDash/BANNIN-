package zap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// freePort asks the OS for an unused TCP port on the loopback interface
// and returns it. There's an unavoidable gap between closing the probe
// listener and ZAP binding the port, but on a local machine that's
// effectively never a problem — and it's far better than ZAP's fixed
// 8080 default, which reliably collides with `bannin serve`.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// progressWriter tees a process's output stream: everything is appended
// to capture (for the full diagnostic record), and each complete line is
// also forwarded to sink (for live progress). ZAP separates lines with
// both '\n' and '\r' (carriage returns for its in-place progress bars),
// so both are treated as delimiters and blank lines are dropped, leaving
// only meaningful updates. sink may be nil, in which case it's pure
// capture. It's written to from the exec goroutine only, so it needs no
// locking of its own.
type progressWriter struct {
	capture *bytes.Buffer
	sink    plugin.ProgressFunc
	partial []byte
}

func (w *progressWriter) Write(p []byte) (int, error) {
	w.capture.Write(p)
	if w.sink == nil {
		return len(p), nil
	}
	w.partial = append(w.partial, p...)
	for {
		i := bytes.IndexAny(w.partial, "\r\n")
		if i < 0 {
			break
		}
		if line := strings.TrimSpace(string(w.partial[:i])); line != "" {
			w.sink(line)
		}
		w.partial = w.partial[i+1:]
	}
	return len(p), nil
}

// Plugin wraps the OWASP ZAP CLI (https://www.zaproxy.org) in headless
// quick-scan mode. bin is resolved once at construction time and is
// overridable so tests can substitute a fake binary.
type Plugin struct {
	bin     string
	mode    string
	ajax    bool
	browser string
	auth    AuthConfig
}

// AuthConfig mirrors the auth-related knobs from config.ZapAuthConfig,
// kept as the plugin's own type so plugins/zap never imports internal
// packages. cmd/bannin maps config into it. Method is one of "form",
// "json", "header", "browser", or "" (unauthenticated).
type AuthConfig struct {
	Method         string
	LoginURL       string
	Username       string
	Password       string
	UsernameField  string
	PasswordField  string
	Header         string
	Token          string
	LoggedInRegex  string
	LoggedOutRegex string
}

// Scan modes. Quick is a fast spider + light active scan (ZAP's
// -quickurl); Full drives ZAP's automation framework through a real
// spider, passive scan, and the full active-scan policy — the mode that
// actually probes for injection-class vulnerabilities (SQLi, XSS,
// command injection) rather than surfacing only passive header/config
// hygiene. Full takes much longer and is far more aggressive against
// the target.
const (
	ModeQuick = "quick"
	ModeFull  = "full"
)

// New returns a ZAP plugin in quick mode that invokes zap.sh, preferring
// PATH but falling back to the well-known locations install-tools.sh
// installs to. bannin serve is often started by a process (a background
// shell, a service manager, an already-running server predating a fresh
// install) that never picked up a PATH update from a shell profile —
// checking the known install locations directly means ZAP works
// regardless of that.
func New() *Plugin {
	return &Plugin{bin: resolveBin(), mode: ModeQuick}
}

// SetMode selects the scan depth. Anything other than ModeFull (including
// the empty string) is normalized to ModeQuick, so an unset or bad config
// value degrades to the safe, fast default rather than erroring.
func (p *Plugin) SetMode(mode string) {
	if mode == ModeFull {
		p.mode = ModeFull
	} else {
		p.mode = ModeQuick
	}
}

// Mode reports the plugin's current scan mode.
func (p *Plugin) Mode() string { return p.mode }

// SetAjax enables (or disables) the AJAX-spider crawl in full mode and
// picks the headless browser it drives (e.g. "chrome-headless",
// "firefox-headless"). An empty browser keeps the current one. Ignored
// in quick mode.
func (p *Plugin) SetAjax(enabled bool, browser string) {
	p.ajax = enabled
	if browser != "" {
		p.browser = browser
	}
}

// SetAuth configures how full-mode scans authenticate to the target.
func (p *Plugin) SetAuth(a AuthConfig) { p.auth = a }

// browserID returns the configured headless browser, defaulting to
// chrome-headless.
func (p *Plugin) browserID() string {
	if p.browser == "" {
		return "chrome-headless"
	}
	return p.browser
}

func resolveBin() string {
	const name = "zap.sh"
	if _, err := exec.LookPath(name); err == nil {
		return name
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return name
	}
	for _, candidate := range []string{
		filepath.Join(home, ".local", "bin", name),
		filepath.Join(home, ".local", "opt", "zap", name),
		"/Applications/OWASP ZAP.app/Contents/Java/zap.sh",
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return name
}

func (p *Plugin) Name() string { return "zap" }

func (p *Plugin) Version() string {
	out, err := exec.Command(p.bin, "-version").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
}

// HealthCheck confirms the zap.sh binary is present on PATH without
// running a scan.
func (p *Plugin) HealthCheck(ctx context.Context) error {
	if _, err := exec.LookPath(p.bin); err != nil {
		return fmt.Errorf("zap: %q not found on PATH: %w", p.bin, err)
	}
	return nil
}

// Run performs a headless scan of target, which must be a running web
// application's http(s) URL — ZAP is a dynamic scanner and cannot scan a
// directory. In either mode ZAP writes its JSON report to a file rather
// than stdout, so Run stages a temp file and returns its contents as the
// RawResult output; process stdout/stderr are captured as diagnostics.
func (p *Plugin) Run(ctx context.Context, target string) (plugin.RawResult, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return plugin.RawResult{}, fmt.Errorf("zap: target must be a running app's http(s) URL, got %q (directory targets are for the static-analysis plugins)", target)
	}

	dir, err := os.MkdirTemp("", "bannin-zap-")
	if err != nil {
		return plugin.RawResult{}, fmt.Errorf("zap: staging report file: %w", err)
	}
	defer os.RemoveAll(dir)
	reportPath := filepath.Join(dir, "report.json")

	args, err := p.buildArgs(dir, target, reportPath)
	if err != nil {
		return plugin.RawResult{}, err
	}

	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	// ZAP streams live progress to stdout (spider/active-scan phases and
	// percentages), so tee stdout through a line splitter that forwards
	// each line to the context's progress sink while still capturing the
	// full output for diagnostics. A scan can run for minutes; this is
	// what lets the dashboard show what's executing instead of just
	// "running".
	cmd.Stdout = &progressWriter{capture: &stdout, sink: plugin.Progress(ctx)}
	cmd.Stderr = &stderr

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return plugin.RawResult{}, fmt.Errorf("zap: run: %w", err)
		}
		exitCode = exitErr.ExitCode()
	}

	// Diagnostics from both streams; the report itself is the output.
	diag := append(stdout.Bytes(), stderr.Bytes()...)
	report, err := os.ReadFile(reportPath)
	if err != nil {
		// No report written — Parse will fail this plugin using the exit
		// code and diagnostics.
		return plugin.RawResult{Stderr: diag, ExitCode: exitCode}, nil
	}
	return plugin.RawResult{Output: report, Stderr: diag, ExitCode: exitCode}, nil
}

// buildArgs assembles the zap.sh arguments for the plugin's mode, both
// producing their JSON report at reportPath. Full mode writes an
// automation-framework plan into dir and runs it; quick mode uses
// -quickurl. Either way ZAP starts a local proxy that defaults to port
// 8080 — the same port `bannin serve` typically uses — so both get an
// OS-assigned free port via -port to avoid "Address already in use".
//
// Header ("token") auth isn't a context authentication method — it's a
// static header injected on every request — so it's wired via ZAP's
// Replacer add-on through -config args rather than the plan YAML.
func (p *Plugin) buildArgs(dir, target, reportPath string) ([]string, error) {
	var args []string
	switch p.mode {
	case ModeFull:
		planPath := filepath.Join(dir, "plan.yaml")
		if err := os.WriteFile(planPath, []byte(p.fullScanPlan(target, dir)), 0o600); err != nil {
			return nil, fmt.Errorf("zap: writing scan plan: %w", err)
		}
		args = []string{"-cmd", "-autorun", planPath}
		if p.auth.Method == "header" {
			args = append(args, headerAuthConfigArgs(p.auth)...)
		}
	default:
		args = []string{"-cmd", "-quickurl", target, "-quickout", reportPath, "-quickprogress"}
	}
	if port, err := freePort(); err == nil {
		args = append(args, "-port", strconv.Itoa(port))
	}
	return args, nil
}

// headerAuthConfigArgs builds the -config args that register a ZAP
// Replacer rule injecting a static auth header (e.g. Authorization:
// Bearer …) into every request, so token/API-authenticated targets are
// scanned as an authenticated client. The header name defaults to
// Authorization.
func headerAuthConfigArgs(a AuthConfig) []string {
	name := a.Header
	if name == "" {
		name = "Authorization"
	}
	set := func(k, v string) string { return "replacer.full_list(0)." + k + "=" + v }
	return []string{
		"-config", set("description", "bannin-auth"),
		"-config", set("enabled", "true"),
		"-config", set("matchtype", "REQ_HEADER"),
		"-config", set("matchstr", name),
		"-config", set("regex", "false"),
		"-config", set("replacement", a.Token),
		"-config", set("initiators", ""),
	}
}

// fullScanPlan renders a ZAP automation-framework plan: (optionally
// authenticated) spider the target, optionally AJAX-spider it with a
// headless browser for JS apps, wait for passive scanning to drain, run
// the full active-scan policy, then emit a traditional-json report to
// dir/report.json (the report job appends .json to reportFile). Every
// interpolated value is JSON-encoded so a hostile URL, path, or
// credential can't break out of the YAML — any JSON scalar is valid YAML.
//
// The context is scoped by includePaths to the target's host on any
// port, not just the exact start URL. Without that, the automation
// spider stays on the single start URL's host:port and never follows
// links to sibling apps the same host serves on other ports — so the
// active scan never reaches them. (ZAP's -quickurl traditional spider
// crawls those by default, which is why quick mode can actually reach
// more of a multi-port target than a naively-scoped full scan.)
//
// The spider and active scan are time-bounded (see the max* parameters)
// so the plan always finishes and writes its report well within the
// caller's scan timeout. A broad target can spider into hundreds of
// URLs; an unbounded active scan of all of them can run for hours and
// then get killed by the timeout mid-flight, writing no report at all —
// bounded, it returns real (if not exhaustive) results every time.
func (p *Plugin) fullScanPlan(target, dir string) string {
	t := jsonString(target)
	// user is set on crawl/scan jobs only when the context carries a
	// login (form/json/browser); header auth injects globally and needs
	// no context user.
	user := ""
	if p.usesContextAuth() {
		user = "\n      user: bannin-user"
	}

	var b strings.Builder
	b.WriteString("env:\n")
	b.WriteString("  contexts:\n")
	b.WriteString("    - name: bannin\n")
	b.WriteString("      urls: [" + t + "]\n")
	b.WriteString("      includePaths:\n")
	b.WriteString("        - " + jsonString(scopeRegex(target)) + "\n")
	b.WriteString(p.authContextYAML(target))
	b.WriteString("  parameters:\n")
	b.WriteString("    progressToStdout: true\n")
	b.WriteString("jobs:\n")
	b.WriteString("  - type: spider\n")
	b.WriteString("    parameters:\n")
	b.WriteString("      context: bannin\n")
	b.WriteString("      url: " + t + "\n")
	b.WriteString("      maxDuration: 5" + user + "\n")
	if p.ajax {
		b.WriteString("  - type: spiderAjax\n")
		b.WriteString("    parameters:\n")
		b.WriteString("      context: bannin\n")
		b.WriteString("      url: " + t + "\n")
		b.WriteString("      browserId: " + jsonString(p.browserID()) + "\n")
		b.WriteString("      maxDuration: 5" + user + "\n")
	}
	b.WriteString("  - type: passiveScan-wait\n")
	b.WriteString("    parameters:\n")
	b.WriteString("      maxDuration: 5\n")
	b.WriteString("  - type: activeScan\n")
	b.WriteString("    parameters:\n")
	b.WriteString("      context: bannin\n")
	b.WriteString("      maxScanDurationInMins: 20\n")
	b.WriteString("      maxRuleDurationInMins: 3" + user + "\n")
	b.WriteString("  - type: report\n")
	b.WriteString("    parameters:\n")
	b.WriteString("      template: traditional-json\n")
	b.WriteString("      reportDir: " + jsonString(dir) + "\n")
	b.WriteString("      reportFile: report\n")
	return b.String()
}

// usesContextAuth reports whether the auth method is one carried on the
// ZAP context (a login the spider/scanner performs), as opposed to
// header auth (a globally-injected static header) or no auth.
func (p *Plugin) usesContextAuth() bool {
	switch p.auth.Method {
	case "form", "json", "browser":
		return true
	default:
		return false
	}
}

// authContextYAML renders the authentication / sessionManagement / users
// block nested under the context (6-space indent), or "" when there's no
// context-carried login. Field names and credentials are JSON-encoded.
func (p *Plugin) authContextYAML(target string) string {
	if !p.usesContextAuth() {
		return ""
	}
	a := p.auth
	loginURL := a.LoginURL
	userField := a.UsernameField
	if userField == "" {
		userField = "username"
	}
	passField := a.PasswordField
	if passField == "" {
		passField = "password"
	}

	var b strings.Builder
	b.WriteString("      authentication:\n")
	b.WriteString("        method: " + jsonString(a.Method) + "\n")
	b.WriteString("        parameters:\n")
	switch a.Method {
	case "browser":
		b.WriteString("          loginPageUrl: " + jsonString(loginURL) + "\n")
		b.WriteString("          browserId: " + jsonString(p.browserID()) + "\n")
	case "json":
		body := `{"` + userField + `":"{%username%}","` + passField + `":"{%password%}"}`
		b.WriteString("          loginPageUrl: " + jsonString(loginURL) + "\n")
		b.WriteString("          loginRequestUrl: " + jsonString(loginURL) + "\n")
		b.WriteString("          loginRequestBody: " + jsonString(body) + "\n")
	default: // form
		body := userField + "={%username%}&" + passField + "={%password%}"
		b.WriteString("          loginPageUrl: " + jsonString(loginURL) + "\n")
		b.WriteString("          loginRequestUrl: " + jsonString(loginURL) + "\n")
		b.WriteString("          loginRequestBody: " + jsonString(body) + "\n")
	}
	b.WriteString("        verification:\n")
	if a.LoggedInRegex != "" || a.LoggedOutRegex != "" {
		b.WriteString("          method: response\n")
		if a.LoggedInRegex != "" {
			b.WriteString("          loggedInRegex: " + jsonString(a.LoggedInRegex) + "\n")
		}
		if a.LoggedOutRegex != "" {
			b.WriteString("          loggedOutRegex: " + jsonString(a.LoggedOutRegex) + "\n")
		}
	} else {
		// No indicator supplied — let ZAP infer session state as best it
		// can rather than assuming every response is authenticated.
		b.WriteString("          method: autodetect\n")
	}
	b.WriteString("      sessionManagement:\n")
	b.WriteString("        method: cookie\n")
	b.WriteString("      users:\n")
	b.WriteString("        - name: bannin-user\n")
	b.WriteString("          credentials:\n")
	b.WriteString("            username: " + jsonString(a.Username) + "\n")
	b.WriteString("            password: " + jsonString(a.Password) + "\n")
	return b.String()
}

// scopeRegex builds a ZAP includePaths regex matching the target's host
// on any port (and any path) — broad enough to crawl sibling apps the
// host serves on other ports, but still confined to that one host so the
// active scanner never attacks anything else. It intentionally does not
// widen to subdomains. A target that won't parse falls back to ".*",
// preserving the previous (unscoped) behavior rather than erroring.
func scopeRegex(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return ".*"
	}
	return `https?://` + regexp.QuoteMeta(u.Hostname()) + `(:[0-9]+)?/.*`
}

// jsonString renders s as a JSON string literal (which is also a valid
// YAML scalar), used to safely embed untrusted values in the plan YAML.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// Parse decodes ZAP's JSON report into normalized Findings, one per
// (site, alert).
func (p *Plugin) Parse(raw plugin.RawResult) ([]plugin.Finding, error) {
	// ZAP's -cmd quick scan exits 0 on a completed scan regardless of
	// how many alerts it raised; any nonzero code is a tool failure.
	if raw.ExitCode != 0 {
		return nil, fmt.Errorf("zap: exited %d: %s", raw.ExitCode, strings.TrimSpace(string(raw.Stderr)))
	}
	if len(raw.Output) == 0 {
		return nil, fmt.Errorf("zap: scan completed but wrote no report: %s", strings.TrimSpace(string(raw.Stderr)))
	}

	var out zapOutput
	if err := json.Unmarshal(raw.Output, &out); err != nil {
		return nil, fmt.Errorf("zap: parsing report: %w", err)
	}

	var findings []plugin.Finding
	for _, site := range out.Site {
		for _, alert := range site.Alerts {
			uri := site.Name
			method := ""
			if len(alert.Instances) > 0 {
				uri = alert.Instances[0].URI
				method = alert.Instances[0].Method
			}

			findings = append(findings, plugin.Finding{
				ID:          alert.PluginID + ":" + uri,
				Scanner:     p.Name(),
				RuleID:      alert.PluginID,
				Category:    plugin.CategoryDAST,
				Title:       alert.Alert,
				Description: stripTags(alert.Desc),
				Severity:    mapRiskCode(alert.RiskCode),
				Location:    plugin.Location{Path: uri},
				CWE:         cwe(alert.CWEID),
				References:  urlsFrom(alert.Reference),
				Metadata: map[string]string{
					"risk":     alert.RiskDesc,
					"method":   method,
					"solution": stripTags(alert.Solution),
				},
			})
		}
	}
	return findings, nil
}

func cwe(id string) []string {
	if id == "" || id == "-1" || id == "0" {
		return nil
	}
	return []string{"CWE-" + id}
}

// mapRiskCode maps ZAP's risk codes (3 high, 2 medium, 1 low, 0
// informational — ZAP has no critical tier) onto plugin.Severity.
func mapRiskCode(code string) plugin.Severity {
	switch code {
	case "3":
		return plugin.SeverityHigh
	case "2":
		return plugin.SeverityMedium
	case "1":
		return plugin.SeverityLow
	case "0":
		return plugin.SeverityInfo
	default:
		return plugin.SeverityMedium
	}
}

var _ plugin.Scanner = (*Plugin)(nil)
