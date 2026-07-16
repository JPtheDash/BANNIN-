package trivy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// fakeTrivy writes a stand-in "trivy" executable to a temp dir and
// returns its path, so Run/HealthCheck/Version can be exercised against
// real process execution without requiring Trivy to actually be
// installed. It answers "--version" and otherwise prints a canned
// findings payload (one vulnerability, one misconfiguration) to stdout,
// a diagnostic line to stderr, and exits 1 (per --exit-code 1).
func fakeTrivy(t *testing.T) string {
	t.Helper()

	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "Version: 0.72.0-fake"
  echo "Vulnerability DB:"
  exit 0
fi
cat <<'EOF'
{"Results":[{"Target":"go.mod","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-39824","PkgName":"golang.org/x/sys","InstalledVersion":"0.29.0","FixedVersion":"0.44.0","Title":"Integer overflow","Description":"desc","Severity":"UNKNOWN","CweIDs":["CWE-190"],"References":["https://go.dev/cl/770080"]}]},{"Target":"Dockerfile","Misconfigurations":[{"ID":"DS-0001","Title":"latest tag used","Message":"Specify a tag","Severity":"MEDIUM","References":["https://avd.aquasec.com/misconfig/ds-0001"],"CauseMetadata":{"StartLine":1,"EndLine":1}}]}]}
EOF
echo "diagnostic output" >&2
exit 1
`
	path := filepath.Join(t.TempDir(), "trivy")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestName(t *testing.T) {
	if got := New().Name(); got != "trivy" {
		t.Errorf("Name() = %q, want %q", got, "trivy")
	}
}

func TestVersionUsesFakeBinary(t *testing.T) {
	p := &Plugin{bin: fakeTrivy(t)}
	if got := p.Version(); got != "0.72.0-fake" {
		t.Errorf("Version() = %q, want %q", got, "0.72.0-fake")
	}
}

func TestVersionMissingBinary(t *testing.T) {
	p := &Plugin{bin: "trivy-does-not-exist-xyz"}
	if got := p.Version(); got != "unknown" {
		t.Errorf("Version() = %q, want %q", got, "unknown")
	}
}

func TestHealthCheckPresent(t *testing.T) {
	p := &Plugin{bin: fakeTrivy(t)}
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck returned error: %v", err)
	}
}

func TestHealthCheckMissing(t *testing.T) {
	p := &Plugin{bin: "trivy-does-not-exist-xyz"}
	if err := p.HealthCheck(context.Background()); err == nil {
		t.Error("HealthCheck should error when the binary isn't on PATH")
	}
}

func TestRunAndParseEndToEnd(t *testing.T) {
	p := &Plugin{bin: fakeTrivy(t)}

	raw, err := p.Run(context.Background(), "./testdata")
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if raw.ExitCode != 1 {
		t.Errorf("RawResult.ExitCode = %d, want 1 (findings reported)", raw.ExitCode)
	}
	if !strings.Contains(string(raw.Stderr), "diagnostic output") {
		t.Errorf("RawResult.Stderr = %q, want it to contain %q", raw.Stderr, "diagnostic output")
	}

	findings, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one vuln, one misconfig)", len(findings))
	}

	vuln := findings[0]
	if vuln.RuleID != "CVE-2026-39824" {
		t.Errorf("vuln Finding.RuleID = %q, want the vulnerability id", vuln.RuleID)
	}
	if vuln.Severity != plugin.SeverityMedium {
		t.Errorf("vuln Finding.Severity = %q, want %q (UNKNOWN defaults to medium)", vuln.Severity, plugin.SeverityMedium)
	}
	if vuln.Metadata["fixed_version"] != "0.44.0" {
		t.Errorf("vuln Finding.Metadata[fixed_version] = %q, want %q", vuln.Metadata["fixed_version"], "0.44.0")
	}
	if len(vuln.CWE) != 1 || vuln.CWE[0] != "CWE-190" {
		t.Errorf("vuln Finding.CWE = %v, want [CWE-190]", vuln.CWE)
	}

	misconfig := findings[1]
	if misconfig.RuleID != "DS-0001" {
		t.Errorf("misconfig Finding.RuleID = %q, want %q", misconfig.RuleID, "DS-0001")
	}
	if misconfig.Severity != plugin.SeverityMedium {
		t.Errorf("misconfig Finding.Severity = %q, want %q", misconfig.Severity, plugin.SeverityMedium)
	}
	if misconfig.Location.Path != "Dockerfile" || misconfig.Location.StartLine != 1 {
		t.Errorf("misconfig Finding.Location = %+v, want Path=Dockerfile StartLine=1", misconfig.Location)
	}
	if misconfig.Description != "Specify a tag" {
		t.Errorf("misconfig Finding.Description = %q, want the Message field", misconfig.Description)
	}
}

func TestParseRejectsGenuineFailureExitCode(t *testing.T) {
	p := New()
	raw := plugin.RawResult{ExitCode: 2, Stderr: []byte("FATAL: could not connect to registry")}

	if _, err := p.Parse(raw); err == nil {
		t.Fatal("Parse should reject an exit code other than 0 or 1")
	} else if !strings.Contains(err.Error(), "could not connect") {
		t.Errorf("Parse error = %v, want it to include stderr", err)
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	p := New()
	raw := plugin.RawResult{ExitCode: 0, Output: []byte("not json")}

	if _, err := p.Parse(raw); err == nil {
		t.Fatal("Parse should reject malformed JSON output")
	}
}

func TestParseSeverityMapping(t *testing.T) {
	cases := []struct {
		trivy string
		want  plugin.Severity
	}{
		{"CRITICAL", plugin.SeverityCritical},
		{"HIGH", plugin.SeverityHigh},
		{"MEDIUM", plugin.SeverityMedium},
		{"LOW", plugin.SeverityLow},
		{"UNKNOWN", plugin.SeverityMedium},
	}

	p := New()
	for _, c := range cases {
		raw := plugin.RawResult{
			ExitCode: 1,
			Output:   []byte(`{"Results":[{"Target":"go.mod","Vulnerabilities":[{"VulnerabilityID":"X","Severity":"` + c.trivy + `"}]}]}`),
		}
		findings, err := p.Parse(raw)
		if err != nil {
			t.Fatalf("Parse returned error for severity %q: %v", c.trivy, err)
		}
		if got := findings[0].Severity; got != c.want {
			t.Errorf("severity %q mapped to %q, want %q", c.trivy, got, c.want)
		}
	}
}

var _ plugin.Scanner = New()
