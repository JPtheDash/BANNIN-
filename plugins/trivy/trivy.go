package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// Plugin wraps the Trivy CLI (https://trivy.dev). bin is the executable
// invoked for Version, HealthCheck, and Run; it defaults to "trivy"
// resolved from PATH, and is overridable (see New) so tests can point it
// at a fake binary instead of requiring the real tool installed.
type Plugin struct {
	bin string
}

// New returns a Trivy plugin that invokes "trivy" from PATH.
func New() *Plugin {
	return &Plugin{bin: "trivy"}
}

func (p *Plugin) Name() string { return "trivy" }

func (p *Plugin) Version() string {
	out, err := exec.Command(p.bin, "--version").Output()
	if err != nil {
		return "unknown"
	}
	line := strings.SplitN(string(out), "\n", 2)[0]
	if _, v, found := strings.Cut(line, "Version: "); found {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(line)
}

// HealthCheck confirms the trivy binary is present on PATH without
// running a scan.
func (p *Plugin) HealthCheck(ctx context.Context) error {
	if _, err := exec.LookPath(p.bin); err != nil {
		return fmt.Errorf("trivy: %q not found on PATH: %w", p.bin, err)
	}
	return nil
}

// Run invokes `trivy fs --scanners vuln,misconfig --format json
// --exit-code 1 --quiet --skip-version-check <target>` and returns its
// raw output. Trivy's default exit code is 0 regardless of findings
// unless --exit-code is set explicitly; setting it to 1 gives the same
// 0/1 "found something" convention plugins/semgrep and plugins/osv use.
func (p *Plugin) Run(ctx context.Context, target string) (plugin.RawResult, error) {
	cmd := exec.CommandContext(ctx, p.bin,
		"fs",
		"--scanners", "vuln,misconfig",
		"--format", "json",
		"--exit-code", "1",
		"--quiet",
		"--skip-version-check",
		target,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return plugin.RawResult{}, fmt.Errorf("trivy: run: %w", err)
		}
		exitCode = exitErr.ExitCode()
	}

	return plugin.RawResult{Output: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: exitCode}, nil
}

// Parse decodes Trivy's JSON output into normalized Findings, combining
// dependency vulnerabilities and IaC misconfigurations into the same
// Finding model.
func (p *Plugin) Parse(raw plugin.RawResult) ([]plugin.Finding, error) {
	// 0 = nothing found, 1 = findings reported (per --exit-code 1 above).
	// Anything else means Trivy itself failed.
	if raw.ExitCode != 0 && raw.ExitCode != 1 {
		return nil, fmt.Errorf("trivy: exited %d: %s", raw.ExitCode, strings.TrimSpace(string(raw.Stderr)))
	}

	var out trivyOutput
	if err := json.Unmarshal(raw.Output, &out); err != nil {
		return nil, fmt.Errorf("trivy: parsing output: %w", err)
	}

	var findings []plugin.Finding
	for _, result := range out.Results {
		for _, v := range result.Vulnerabilities {
			findings = append(findings, plugin.Finding{
				ID:          v.VulnerabilityID + ":" + v.PkgName + "@" + v.InstalledVersion,
				Scanner:     p.Name(),
				RuleID:      v.VulnerabilityID,
				Category:    plugin.CategorySCA,
				Title:       title(v.Title, v.VulnerabilityID),
				Description: v.Description,
				Severity:    mapSeverity(v.Severity),
				Location:    plugin.Location{Path: result.Target},
				CWE:         v.CweIDs,
				References:  v.References,
				Metadata: map[string]string{
					"package":       v.PkgName,
					"version":       v.InstalledVersion,
					"fixed_version": v.FixedVersion,
				},
			})
		}
		for _, m := range result.Misconfigurations {
			findings = append(findings, plugin.Finding{
				ID:          m.ID + ":" + result.Target,
				Scanner:     p.Name(),
				RuleID:      m.ID,
				Category:    plugin.CategoryIaC,
				Title:       title(m.Title, m.ID),
				Description: description(m),
				Severity:    mapSeverity(m.Severity),
				Location: plugin.Location{
					Path:      result.Target,
					StartLine: m.CauseMetadata.StartLine,
					EndLine:   m.CauseMetadata.EndLine,
				},
				References: m.References,
			})
		}
	}
	return findings, nil
}

func title(t, fallback string) string {
	if t != "" {
		return t
	}
	return fallback
}

func description(m trivyMisconfiguration) string {
	if m.Message != "" {
		return m.Message
	}
	return m.Description
}

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
	default: // "UNKNOWN" or anything unrecognized
		return plugin.SeverityMedium
	}
}

var _ plugin.Scanner = (*Plugin)(nil)
