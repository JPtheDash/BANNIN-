package osv

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

// Plugin wraps the OSV Scanner CLI (https://google.github.io/osv-scanner).
// bin is the executable invoked for Version, HealthCheck, and Run; it
// defaults to "osv-scanner" resolved from PATH, and is overridable (see
// New) so tests can point it at a fake binary instead of requiring the
// real tool installed.
type Plugin struct {
	bin string
}

// New returns an OSV Scanner plugin that invokes "osv-scanner" from PATH.
func New() *Plugin {
	return &Plugin{bin: "osv-scanner"}
}

func (p *Plugin) Name() string { return "osv" }

func (p *Plugin) Version() string {
	out, err := exec.Command(p.bin, "--version").Output()
	if err != nil {
		return "unknown"
	}
	line := strings.SplitN(string(out), "\n", 2)[0]
	if _, v, found := strings.Cut(line, "version: "); found {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(line)
}

// HealthCheck confirms the osv-scanner binary is present on PATH without
// running a scan.
func (p *Plugin) HealthCheck(ctx context.Context) error {
	if _, err := exec.LookPath(p.bin); err != nil {
		return fmt.Errorf("osv: %q not found on PATH: %w", p.bin, err)
	}
	return nil
}

// Run invokes `osv-scanner scan source --recursive --all-vulns
// --allow-no-lockfiles --format json <target>` and returns its raw
// output. --allow-no-lockfiles keeps "nothing to scan here" (e.g. a
// target with no dependency manifest) from being treated as a failure;
// --all-vulns makes the exit code reflect every vulnerability found, not
// just ones OSV Scanner judges "important". Like Semgrep, a nonzero exit
// here can mean "found something", not "tool failed" — that judgment
// happens in Parse.
func (p *Plugin) Run(ctx context.Context, target string) (plugin.RawResult, error) {
	cmd := exec.CommandContext(ctx, p.bin,
		"scan", "source",
		"--recursive",
		"--all-vulns",
		"--allow-no-lockfiles",
		"--format", "json",
		target,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return plugin.RawResult{}, fmt.Errorf("osv: run: %w", err)
		}
		exitCode = exitErr.ExitCode()
	}

	return plugin.RawResult{Output: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: exitCode}, nil
}

// Parse decodes OSV Scanner's JSON output into normalized Findings, one
// per (package, vulnerability) pair.
func (p *Plugin) Parse(raw plugin.RawResult) ([]plugin.Finding, error) {
	// 0 = no vulnerabilities, 1 = vulnerabilities found (with --all-vulns).
	// Anything else means osv-scanner itself failed.
	if raw.ExitCode != 0 && raw.ExitCode != 1 {
		return nil, fmt.Errorf("osv: exited %d: %s", raw.ExitCode, strings.TrimSpace(string(raw.Stderr)))
	}

	var out osvOutput
	if err := json.Unmarshal(raw.Output, &out); err != nil {
		return nil, fmt.Errorf("osv: parsing output: %w", err)
	}

	var findings []plugin.Finding
	for _, result := range out.Results {
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				findings = append(findings, plugin.Finding{
					ID:          vuln.ID + ":" + pkg.Package.Name + "@" + pkg.Package.Version,
					Scanner:     p.Name(),
					RuleID:      vuln.ID,
					Aliases:     vuln.Aliases,
					Title:       vuln.ID,
					Description: description(vuln),
					Severity:    mapSeverity(vuln),
					Location:    plugin.Location{Path: result.Source.Path},
					References:  references(vuln),
					Metadata: map[string]string{
						"package":   pkg.Package.Name,
						"version":   pkg.Package.Version,
						"ecosystem": pkg.Package.Ecosystem,
					},
				})
			}
		}
	}
	return findings, nil
}

func description(v osvVulnerability) string {
	if v.Summary != "" {
		return v.Summary
	}
	return v.Details
}

func references(v osvVulnerability) []string {
	refs := make([]string, 0, len(v.References))
	for _, r := range v.References {
		refs = append(refs, r.URL)
	}
	return refs
}

// mapSeverity maps OSV's inconsistent-across-ecosystems severity
// reporting onto plugin.Severity: prefer an explicit textual severity
// (common for GitHub Security Advisory-sourced entries), fall back to a
// numeric CVSS score if present, and default to medium when a real
// vulnerability exists but carries no severity signal at all (many Go
// vulndb entries, for example).
func mapSeverity(v osvVulnerability) plugin.Severity {
	switch strings.ToUpper(v.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return plugin.SeverityCritical
	case "HIGH":
		return plugin.SeverityHigh
	case "MODERATE", "MEDIUM":
		return plugin.SeverityMedium
	case "LOW":
		return plugin.SeverityLow
	}

	for _, sev := range v.Severity {
		score, err := strconv.ParseFloat(sev.Score, 64)
		if err != nil {
			continue
		}
		switch {
		case score >= 9.0:
			return plugin.SeverityCritical
		case score >= 7.0:
			return plugin.SeverityHigh
		case score >= 4.0:
			return plugin.SeverityMedium
		default:
			return plugin.SeverityLow
		}
	}

	return plugin.SeverityMedium
}

var _ plugin.Scanner = (*Plugin)(nil)
