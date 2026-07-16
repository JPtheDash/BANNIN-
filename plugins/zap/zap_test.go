package zap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// fakeZap writes a stand-in "zap.sh" to a temp dir. It answers
// "-version", and for a scan it locates the -quickout argument, writes
// the canned JSON report to that path (mimicking ZAP's report-to-file
// behavior), prints progress to stdout, and exits 0.
func fakeZap(t *testing.T) string {
	t.Helper()

	script := `#!/bin/sh
if [ "$1" = "-version" ]; then
  echo "2.17.0-fake"
  exit 0
fi
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-quickout" ]; then out="$arg"; fi
  prev="$arg"
done
cat > "$out" <<'EOF'
{"site":[{"@name":"http://127.0.0.1:5000","alerts":[{"pluginid":"10038","alert":"Content Security Policy (CSP) Header Not Set","riskcode":"2","riskdesc":"Medium (High)","desc":"<p>CSP helps detect and mitigate certain attacks.</p>","solution":"<p>Set the CSP header.</p>","reference":"<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP</p><p>https://owasp.org/www-community/controls/Content_Security_Policy</p>","cweid":"693","instances":[{"uri":"http://127.0.0.1:5000/login","method":"GET"}]}]}]}
EOF
echo "Attack complete"
exit 0
`
	path := filepath.Join(t.TempDir(), "zap.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestName(t *testing.T) {
	if got := New().Name(); got != "zap" {
		t.Errorf("Name() = %q, want %q", got, "zap")
	}
}

func TestVersionUsesFakeBinary(t *testing.T) {
	p := &Plugin{bin: fakeZap(t)}
	if got := p.Version(); got != "2.17.0-fake" {
		t.Errorf("Version() = %q, want %q", got, "2.17.0-fake")
	}
}

func TestHealthCheckMissing(t *testing.T) {
	p := &Plugin{bin: "zap-does-not-exist-xyz"}
	if err := p.HealthCheck(context.Background()); err == nil {
		t.Error("HealthCheck should error when the binary isn't on PATH")
	}
}

func TestRunRejectsNonURLTarget(t *testing.T) {
	p := &Plugin{bin: fakeZap(t)}
	if _, err := p.Run(context.Background(), "./some/directory"); err == nil {
		t.Fatal("Run should reject a non-URL target: ZAP scans running apps, not directories")
	}
}

func TestRunAndParseEndToEnd(t *testing.T) {
	p := &Plugin{bin: fakeZap(t)}

	raw, err := p.Run(context.Background(), "http://127.0.0.1:5000")
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if raw.ExitCode != 0 {
		t.Errorf("RawResult.ExitCode = %d, want 0", raw.ExitCode)
	}
	if len(raw.Output) == 0 {
		t.Fatal("Run did not capture the report file ZAP wrote")
	}
	if !strings.Contains(string(raw.Stderr), "Attack complete") {
		t.Errorf("RawResult.Stderr = %q, want process output captured as diagnostics", raw.Stderr)
	}

	findings, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "10038" || f.Title != "Content Security Policy (CSP) Header Not Set" {
		t.Errorf("Finding rule/title = %q/%q, want ZAP alert fields", f.RuleID, f.Title)
	}
	if f.Severity != plugin.SeverityMedium {
		t.Errorf("Finding.Severity = %q, want %q (riskcode 2)", f.Severity, plugin.SeverityMedium)
	}
	if f.Location.Path != "http://127.0.0.1:5000/login" {
		t.Errorf("Finding.Location.Path = %q, want the instance URI", f.Location.Path)
	}
	if strings.Contains(f.Description, "<p>") {
		t.Errorf("Finding.Description = %q, want ZAP's embedded HTML stripped", f.Description)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-693" {
		t.Errorf("Finding.CWE = %v, want [CWE-693]", f.CWE)
	}
	if len(f.References) != 2 || !strings.HasPrefix(f.References[0], "https://developer.mozilla.org") {
		t.Errorf("Finding.References = %v, want the two URLs extracted from the reference HTML", f.References)
	}
	if f.Metadata["method"] != "GET" || f.Metadata["risk"] != "Medium (High)" {
		t.Errorf("Finding.Metadata = %v, want method and risk recorded", f.Metadata)
	}
}

func TestParseRiskCodeMapping(t *testing.T) {
	cases := []struct {
		code string
		want plugin.Severity
	}{
		{"3", plugin.SeverityHigh},
		{"2", plugin.SeverityMedium},
		{"1", plugin.SeverityLow},
		{"0", plugin.SeverityInfo},
		{"weird", plugin.SeverityMedium},
	}
	p := New()
	for _, c := range cases {
		raw := plugin.RawResult{
			ExitCode: 0,
			Output:   []byte(`{"site":[{"@name":"http://x","alerts":[{"pluginid":"1","alert":"a","riskcode":"` + c.code + `"}]}]}`),
		}
		findings, err := p.Parse(raw)
		if err != nil {
			t.Fatalf("Parse returned error for riskcode %q: %v", c.code, err)
		}
		if got := findings[0].Severity; got != c.want {
			t.Errorf("riskcode %q mapped to %q, want %q", c.code, got, c.want)
		}
	}
}

func TestParseToolFailure(t *testing.T) {
	p := New()
	raw := plugin.RawResult{ExitCode: 1, Stderr: []byte("java not found")}

	if _, err := p.Parse(raw); err == nil {
		t.Fatal("Parse should reject a nonzero exit code")
	} else if !strings.Contains(err.Error(), "java not found") {
		t.Errorf("Parse error = %v, want diagnostics included", err)
	}
}

func TestParseNoReportWritten(t *testing.T) {
	p := New()
	raw := plugin.RawResult{ExitCode: 0, Output: nil, Stderr: []byte("startup failed silently")}

	if _, err := p.Parse(raw); err == nil {
		t.Fatal("Parse should fail when the scan produced no report at all")
	}
}

var _ plugin.Scanner = New()
