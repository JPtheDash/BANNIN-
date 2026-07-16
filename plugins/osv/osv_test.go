package osv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// fakeOSVScanner writes a stand-in "osv-scanner" executable to a temp
// dir and returns its path, so Run/HealthCheck/Version can be exercised
// against real process execution without requiring OSV Scanner to
// actually be installed. It answers "--version" and otherwise prints a
// canned vulnerability payload to stdout, a diagnostic line to stderr,
// and exits 1 (vulnerabilities found, with --all-vulns).
func fakeOSVScanner(t *testing.T) string {
	t.Helper()

	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "osv-scanner version: 2.4.0-fake"
  echo "commit: n/a"
  exit 0
fi
cat <<'EOF'
{"results":[{"source":{"path":"go.mod","type":"lockfile"},"packages":[{"package":{"name":"golang.org/x/sys","version":"0.29.0","ecosystem":"Go"},"vulnerabilities":[{"id":"GO-2026-5024","summary":"Integer overflow in NewNTUnicodeString","references":[{"type":"FIX","url":"https://go.dev/cl/770080"}],"database_specific":{"severity":"HIGH"}}]}]}]}
EOF
echo "diagnostic output" >&2
exit 1
`
	path := filepath.Join(t.TempDir(), "osv-scanner")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestName(t *testing.T) {
	if got := New().Name(); got != "osv" {
		t.Errorf("Name() = %q, want %q", got, "osv")
	}
}

func TestVersionUsesFakeBinary(t *testing.T) {
	p := &Plugin{bin: fakeOSVScanner(t)}
	if got := p.Version(); got != "2.4.0-fake" {
		t.Errorf("Version() = %q, want %q", got, "2.4.0-fake")
	}
}

func TestVersionMissingBinary(t *testing.T) {
	p := &Plugin{bin: "osv-scanner-does-not-exist-xyz"}
	if got := p.Version(); got != "unknown" {
		t.Errorf("Version() = %q, want %q", got, "unknown")
	}
}

func TestHealthCheckPresent(t *testing.T) {
	p := &Plugin{bin: fakeOSVScanner(t)}
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck returned error: %v", err)
	}
}

func TestHealthCheckMissing(t *testing.T) {
	p := &Plugin{bin: "osv-scanner-does-not-exist-xyz"}
	if err := p.HealthCheck(context.Background()); err == nil {
		t.Error("HealthCheck should error when the binary isn't on PATH")
	}
}

func TestRunAndParseEndToEnd(t *testing.T) {
	p := &Plugin{bin: fakeOSVScanner(t)}

	raw, err := p.Run(context.Background(), "./testdata")
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if raw.ExitCode != 1 {
		t.Errorf("RawResult.ExitCode = %d, want 1 (vulnerabilities found)", raw.ExitCode)
	}
	if !strings.Contains(string(raw.Stderr), "diagnostic output") {
		t.Errorf("RawResult.Stderr = %q, want it to contain %q", raw.Stderr, "diagnostic output")
	}

	findings, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.Scanner != "osv" {
		t.Errorf("Finding.Scanner = %q, want %q", f.Scanner, "osv")
	}
	if f.RuleID != "GO-2026-5024" {
		t.Errorf("Finding.RuleID = %q, want the vuln id", f.RuleID)
	}
	if f.Severity != plugin.SeverityHigh {
		t.Errorf("Finding.Severity = %q, want %q", f.Severity, plugin.SeverityHigh)
	}
	if f.Location.Path != "go.mod" {
		t.Errorf("Finding.Location.Path = %q, want %q", f.Location.Path, "go.mod")
	}
	if f.Metadata["package"] != "golang.org/x/sys" || f.Metadata["version"] != "0.29.0" {
		t.Errorf("Finding.Metadata = %v, want package/version set", f.Metadata)
	}
	if len(f.References) != 1 || f.References[0] != "https://go.dev/cl/770080" {
		t.Errorf("Finding.References = %v, want [https://go.dev/cl/770080]", f.References)
	}
}

func TestParseNoVulnerabilities(t *testing.T) {
	p := New()
	raw := plugin.RawResult{ExitCode: 0, Output: []byte(`{"results":null}`)}

	findings, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestParseRejectsGenuineFailureExitCode(t *testing.T) {
	p := New()
	raw := plugin.RawResult{ExitCode: 128, Stderr: []byte("No package sources found")}

	if _, err := p.Parse(raw); err == nil {
		t.Fatal("Parse should reject an exit code other than 0 or 1")
	} else if !strings.Contains(err.Error(), "No package sources found") {
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

func TestParseSeverityFallbackToCVSSScore(t *testing.T) {
	p := New()
	raw := plugin.RawResult{
		ExitCode: 1,
		Output:   []byte(`{"results":[{"source":{"path":"package-lock.json"},"packages":[{"package":{"name":"foo","version":"1.0.0","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-xxxx","severity":[{"type":"CVSS_V3","score":"9.8"}]}]}]}]}`),
	}
	findings, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if got := findings[0].Severity; got != plugin.SeverityCritical {
		t.Errorf("Severity = %q, want %q (CVSS 9.8 -> critical)", got, plugin.SeverityCritical)
	}
}

func TestParseSeverityDefaultsToMediumWithNoSignal(t *testing.T) {
	p := New()
	raw := plugin.RawResult{
		ExitCode: 1,
		Output:   []byte(`{"results":[{"source":{"path":"go.mod"},"packages":[{"package":{"name":"foo","version":"1.0.0","ecosystem":"Go"},"vulnerabilities":[{"id":"GO-1"}]}]}]}`),
	}

	findings, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if got := findings[0].Severity; got != plugin.SeverityMedium {
		t.Errorf("Severity = %q, want %q (no severity signal -> medium default)", got, plugin.SeverityMedium)
	}
}

var _ plugin.Scanner = New()
