package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// fakeSemgrep writes a stand-in "semgrep" executable to a temp dir and
// returns its path, so Run/HealthCheck/Version can be exercised against
// real process execution without requiring Semgrep to actually be
// installed. It answers "--version" and otherwise prints a canned
// findings payload to stdout, a diagnostic line to stderr, and exits 1
// (Semgrep's "findings reported" exit code).
func fakeSemgrep(t *testing.T) string {
	t.Helper()

	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "1.99.0-fake"
  exit 0
fi
cat <<'EOF'
{"results":[{"check_id":"python.lang.security.audit.eval-detected","path":"app.py","start":{"line":10},"end":{"line":10},"extra":{"message":"Detected use of eval()","severity":"ERROR","metadata":{"cwe":["CWE-95: Eval Injection"],"references":["https://example.com/eval"]}}}]}
EOF
echo "diagnostic output" >&2
exit 1
`
	path := filepath.Join(t.TempDir(), "semgrep")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestName(t *testing.T) {
	if got := New().Name(); got != "semgrep" {
		t.Errorf("Name() = %q, want %q", got, "semgrep")
	}
}

func TestVersionUsesFakeBinary(t *testing.T) {
	p := &Plugin{bin: fakeSemgrep(t)}
	if got := p.Version(); got != "1.99.0-fake" {
		t.Errorf("Version() = %q, want %q", got, "1.99.0-fake")
	}
}

func TestVersionMissingBinary(t *testing.T) {
	p := &Plugin{bin: "semgrep-does-not-exist-xyz"}
	if got := p.Version(); got != "unknown" {
		t.Errorf("Version() = %q, want %q", got, "unknown")
	}
}

func TestHealthCheckPresent(t *testing.T) {
	p := &Plugin{bin: fakeSemgrep(t)}
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck returned error: %v", err)
	}
}

func TestHealthCheckMissing(t *testing.T) {
	p := &Plugin{bin: "semgrep-does-not-exist-xyz"}
	if err := p.HealthCheck(context.Background()); err == nil {
		t.Error("HealthCheck should error when the binary isn't on PATH")
	}
}

func TestRunAndParseEndToEnd(t *testing.T) {
	p := &Plugin{bin: fakeSemgrep(t)}

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
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.Scanner != "semgrep" {
		t.Errorf("Finding.Scanner = %q, want %q", f.Scanner, "semgrep")
	}
	if f.RuleID != "python.lang.security.audit.eval-detected" {
		t.Errorf("Finding.RuleID = %q, want the check_id", f.RuleID)
	}
	if f.Severity != plugin.SeverityHigh {
		t.Errorf("Finding.Severity = %q, want %q (ERROR maps to high)", f.Severity, plugin.SeverityHigh)
	}
	if f.Location.Path != "app.py" || f.Location.StartLine != 10 {
		t.Errorf("Finding.Location = %+v, want Path=app.py StartLine=10", f.Location)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-95: Eval Injection" {
		t.Errorf("Finding.CWE = %v, want [CWE-95: Eval Injection]", f.CWE)
	}
	if len(f.References) != 1 || f.References[0] != "https://example.com/eval" {
		t.Errorf("Finding.References = %v, want [https://example.com/eval]", f.References)
	}
}

func TestParseRejectsGenuineFailureExitCode(t *testing.T) {
	p := New()
	raw := plugin.RawResult{ExitCode: 2, Stderr: []byte("fatal: invalid config")}

	if _, err := p.Parse(raw); err == nil {
		t.Fatal("Parse should reject an exit code other than 0 or 1")
	} else if !strings.Contains(err.Error(), "invalid config") {
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
		semgrep string
		want    plugin.Severity
	}{
		{"ERROR", plugin.SeverityHigh},
		{"WARNING", plugin.SeverityMedium},
		{"INFO", plugin.SeverityInfo},
		{"WEIRD", plugin.SeverityMedium},
	}

	p := New()
	for _, c := range cases {
		raw := plugin.RawResult{
			ExitCode: 1,
			Output:   []byte(`{"results":[{"check_id":"r","path":"f.go","start":{"line":1},"end":{"line":1},"extra":{"severity":"` + c.semgrep + `"}}]}`),
		}
		findings, err := p.Parse(raw)
		if err != nil {
			t.Fatalf("Parse returned error for severity %q: %v", c.semgrep, err)
		}
		if got := findings[0].Severity; got != c.want {
			t.Errorf("severity %q mapped to %q, want %q", c.semgrep, got, c.want)
		}
	}
}

func TestParseCWEAsSingleString(t *testing.T) {
	p := New()
	raw := plugin.RawResult{
		ExitCode: 1,
		Output:   []byte(`{"results":[{"check_id":"r","path":"f.go","start":{"line":1},"end":{"line":1},"extra":{"severity":"ERROR","metadata":{"cwe":"CWE-79: XSS"}}}]}`),
	}
	findings, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(findings[0].CWE) != 1 || findings[0].CWE[0] != "CWE-79: XSS" {
		t.Errorf("Finding.CWE = %v, want [CWE-79: XSS]", findings[0].CWE)
	}
}

var _ plugin.Scanner = New()
