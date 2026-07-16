package gitleaks

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

// Plugin wraps the Gitleaks CLI (https://gitleaks.io). bin is the
// executable invoked for Version, HealthCheck, and Run; it defaults to
// "gitleaks" resolved from PATH, and is overridable (see New) so tests
// can point it at a fake binary instead of requiring the real tool
// installed.
type Plugin struct {
	bin string
}

// New returns a Gitleaks plugin that invokes "gitleaks" from PATH.
func New() *Plugin {
	return &Plugin{bin: "gitleaks"}
}

func (p *Plugin) Name() string { return "gitleaks" }

func (p *Plugin) Version() string {
	out, err := exec.Command(p.bin, "version").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// HealthCheck confirms the gitleaks binary is present on PATH without
// running a scan.
func (p *Plugin) HealthCheck(ctx context.Context) error {
	if _, err := exec.LookPath(p.bin); err != nil {
		return fmt.Errorf("gitleaks: %q not found on PATH: %w", p.bin, err)
	}
	return nil
}

// Run invokes `gitleaks dir --report-format json --report-path -
// --no-banner --redact <target>` and returns its raw output. `dir` (not
// `git`) scans the working tree rather than commit history, matching how
// the other filesystem-oriented plugins treat the target. --redact is
// non-negotiable: without it the JSON report embeds each leaked secret's
// value, which must not propagate into BANNIN findings. Gitleaks exits 1
// when leaks are found (its default --exit-code), so like the other
// plugins that judgment is deferred to Parse.
func (p *Plugin) Run(ctx context.Context, target string) (plugin.RawResult, error) {
	cmd := exec.CommandContext(ctx, p.bin,
		"dir",
		"--report-format", "json",
		"--report-path", "-",
		"--no-banner",
		"--redact",
		target,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return plugin.RawResult{}, fmt.Errorf("gitleaks: run: %w", err)
		}
		exitCode = exitErr.ExitCode()
	}

	return plugin.RawResult{Output: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: exitCode}, nil
}

// Parse decodes Gitleaks' JSON report (a top-level array of leaks) into
// normalized Findings. Every leak is SeverityHigh: Gitleaks has no
// severity scale of its own, and an exposed credential is never a minor
// issue.
func (p *Plugin) Parse(raw plugin.RawResult) ([]plugin.Finding, error) {
	// 0 = no leaks, 1 = leaks found (gitleaks' default --exit-code).
	// Anything else means gitleaks itself failed.
	if raw.ExitCode != 0 && raw.ExitCode != 1 {
		return nil, fmt.Errorf("gitleaks: exited %d: %s", raw.ExitCode, strings.TrimSpace(string(raw.Stderr)))
	}

	var leaks []gitleaksFinding
	if err := json.Unmarshal(raw.Output, &leaks); err != nil {
		return nil, fmt.Errorf("gitleaks: parsing output: %w", err)
	}

	findings := make([]plugin.Finding, 0, len(leaks))
	for _, l := range leaks {
		findings = append(findings, plugin.Finding{
			ID:          l.Fingerprint,
			Scanner:     p.Name(),
			RuleID:      l.RuleID,
			Title:       "Secret detected: " + l.RuleID,
			Description: l.Description,
			Severity:    plugin.SeverityHigh,
			Location: plugin.Location{
				Path:      l.File,
				StartLine: l.StartLine,
				EndLine:   l.EndLine,
			},
			CWE: []string{"CWE-798"}, // use of hard-coded credentials
		})
	}
	return findings, nil
}

var _ plugin.Scanner = (*Plugin)(nil)
