package semgrep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// Plugin wraps the Semgrep CLI (https://semgrep.dev). bin is the
// executable invoked for Version, HealthCheck, and Run; it defaults to
// "semgrep" resolved from PATH, and is overridable (see New) so tests
// can point it at a fake binary instead of requiring Semgrep installed.
type Plugin struct {
	bin string
}

// New returns a Semgrep plugin that invokes "semgrep" from PATH.
func New() *Plugin {
	return &Plugin{bin: "semgrep"}
}

func (p *Plugin) Name() string { return "semgrep" }

func (p *Plugin) Version() string {
	out, err := exec.Command(p.bin, "--version").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// HealthCheck confirms the semgrep binary is present on PATH without
// running a scan.
func (p *Plugin) HealthCheck(ctx context.Context) error {
	if _, err := exec.LookPath(p.bin); err != nil {
		return fmt.Errorf("semgrep: %q not found on PATH: %w", p.bin, err)
	}
	return nil
}

// Run invokes `semgrep --json --quiet --config=auto <target>` and
// returns its raw output. Semgrep exits 1 when it finds results (not an
// error) and other nonzero codes on genuine failure; Run passes the exit
// code through in RawResult rather than judging it, so Parse can make
// that call against the actual output.
func (p *Plugin) Run(ctx context.Context, target string) (plugin.RawResult, error) {
	cmd := exec.CommandContext(ctx, p.bin, "--json", "--quiet", "--config=auto", target)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return plugin.RawResult{}, fmt.Errorf("semgrep: run: %w", err)
		}
		exitCode = exitErr.ExitCode()
	}

	return plugin.RawResult{Output: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: exitCode}, nil
}

// Parse decodes Semgrep's JSON output into normalized Findings.
func (p *Plugin) Parse(raw plugin.RawResult) ([]plugin.Finding, error) {
	// 0 = no findings, 1 = findings reported. Anything else means Semgrep
	// itself failed (bad config, crash, ...), so the stdout JSON isn't
	// trustworthy.
	if raw.ExitCode != 0 && raw.ExitCode != 1 {
		return nil, fmt.Errorf("semgrep: exited %d: %s", raw.ExitCode, strings.TrimSpace(string(raw.Stderr)))
	}

	var out semgrepOutput
	if err := json.Unmarshal(raw.Output, &out); err != nil {
		return nil, fmt.Errorf("semgrep: parsing output: %w", err)
	}

	findings := make([]plugin.Finding, 0, len(out.Results))
	for _, r := range out.Results {
		findings = append(findings, plugin.Finding{
			ID:          r.CheckID + ":" + r.Path + ":" + strconv.Itoa(r.Start.Line),
			Scanner:     p.Name(),
			RuleID:      r.CheckID,
			Category:    plugin.CategorySAST,
			Title:       r.CheckID,
			Description: r.Extra.Message,
			Severity:    mapSeverity(r.Extra.Severity),
			Location: plugin.Location{
				Path:      r.Path,
				StartLine: r.Start.Line,
				EndLine:   r.End.Line,
			},
			CWE:        []string(r.Extra.Metadata.CWE),
			References: []string(r.Extra.Metadata.References),
		})
	}
	return findings, nil
}

func mapSeverity(s string) plugin.Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return plugin.SeverityHigh
	case "WARNING":
		return plugin.SeverityMedium
	case "INFO":
		return plugin.SeverityInfo
	default:
		return plugin.SeverityMedium
	}
}

var _ plugin.Scanner = (*Plugin)(nil)
