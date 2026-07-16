package checkov

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// Plugin wraps the Checkov CLI (https://www.checkov.io). bin is the
// executable invoked for Version, HealthCheck, and Run; it defaults to
// "checkov" resolved from PATH, and is overridable (see New) so tests
// can point it at a fake binary instead of requiring the real tool
// installed.
type Plugin struct {
	bin string
}

// New returns a Checkov plugin that invokes "checkov" from PATH.
func New() *Plugin {
	return &Plugin{bin: "checkov"}
}

func (p *Plugin) Name() string { return "checkov" }

func (p *Plugin) Version() string {
	out, err := exec.Command(p.bin, "--version").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// HealthCheck confirms the checkov binary is present on PATH without
// running a scan.
func (p *Plugin) HealthCheck(ctx context.Context) error {
	if _, err := exec.LookPath(p.bin); err != nil {
		return fmt.Errorf("checkov: %q not found on PATH: %w", p.bin, err)
	}
	return nil
}

// Run invokes `checkov -d <target> -o json --quiet` and returns its raw
// output. Checkov exits 1 when checks failed (findings, not a tool
// error) and 0 on a clean run — including runs that found nothing
// scannable. Parse interprets the exit code against the output.
func (p *Plugin) Run(ctx context.Context, target string) (plugin.RawResult, error) {
	cmd := exec.CommandContext(ctx, p.bin, "-d", target, "-o", "json", "--quiet")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return plugin.RawResult{}, fmt.Errorf("checkov: run: %w", err)
		}
		exitCode = exitErr.ExitCode()
	}

	return plugin.RawResult{Output: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: exitCode}, nil
}

// Parse decodes Checkov's JSON output into normalized Findings, one per
// failed check.
func (p *Plugin) Parse(raw plugin.RawResult) ([]plugin.Finding, error) {
	// 0 = clean, 1 = failed checks reported. Anything else means Checkov
	// itself failed.
	if raw.ExitCode != 0 && raw.ExitCode != 1 {
		return nil, fmt.Errorf("checkov: exited %d: %s", raw.ExitCode, strings.TrimSpace(string(raw.Stderr)))
	}

	reports, err := decodeReports(raw.Output)
	if err != nil {
		return nil, fmt.Errorf("checkov: parsing output: %w", err)
	}

	var findings []plugin.Finding
	for _, report := range reports {
		for _, check := range report.Results.FailedChecks {
			start, end := check.lines()
			// Checkov writes file paths with a leading slash relative to
			// the scanned directory ("/Dockerfile"); trim it so paths
			// read as target-relative like other plugins'.
			path := strings.TrimPrefix(check.FilePath, "/")

			findings = append(findings, plugin.Finding{
				ID:          check.CheckID + ":" + path + ":" + strconv.Itoa(start),
				Scanner:     p.Name(),
				RuleID:      check.CheckID,
				Title:       check.CheckName,
				Description: check.CheckName,
				Severity:    mapSeverity(check.Severity),
				Location: plugin.Location{
					Path:      path,
					StartLine: start,
					EndLine:   end,
				},
				References: references(check),
				Metadata: map[string]string{
					"check_type": report.CheckType,
					"resource":   check.Resource,
				},
			})
		}
	}
	return findings, nil
}

func references(c checkovCheck) []string {
	if c.Guideline == "" {
		return nil
	}
	return []string{c.Guideline}
}

// mapSeverity maps Checkov severities onto plugin.Severity. The
// open-source build reports no severity at all (it's an enterprise
// feature), so the empty default lands on medium.
func mapSeverity(s string) plugin.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return plugin.SeverityCritical
	case "HIGH":
		return plugin.SeverityHigh
	case "MEDIUM":
		return plugin.SeverityMedium
	case "LOW":
		return plugin.SeverityLow
	case "INFO":
		return plugin.SeverityInfo
	default:
		return plugin.SeverityMedium
	}
}

var _ plugin.Scanner = (*Plugin)(nil)
