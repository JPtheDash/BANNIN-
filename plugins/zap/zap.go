package zap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// Plugin wraps the OWASP ZAP CLI (https://www.zaproxy.org) in headless
// quick-scan mode. bin is resolved once at construction time and is
// overridable so tests can substitute a fake binary.
type Plugin struct {
	bin string
}

// New returns a ZAP plugin that invokes zap.sh, preferring PATH but
// falling back to the well-known locations install-tools.sh installs
// to. bannin serve is often started by a process (a background shell,
// a service manager, an already-running server predating a fresh
// install) that never picked up a PATH update from a shell profile —
// checking the known install locations directly means ZAP works
// regardless of that.
func New() *Plugin {
	return &Plugin{bin: resolveBin()}
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

// Run performs a headless quick scan of target, which must be a running
// web application's http(s) URL — ZAP is a dynamic scanner and cannot
// scan a directory. ZAP writes its JSON report to a file (-quickout)
// rather than stdout, so Run stages a temp file and returns its
// contents as the RawResult output; process stdout/stderr are captured
// as diagnostics.
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

	cmd := exec.CommandContext(ctx, p.bin, "-cmd", "-quickurl", target, "-quickout", reportPath, "-quickprogress")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
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
