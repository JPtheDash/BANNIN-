package gitleaks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// fakeGitleaks writes a stand-in "gitleaks" executable to a temp dir and
// returns its path, so Run/HealthCheck/Version can be exercised against
// real process execution without requiring Gitleaks to actually be
// installed. It answers "version" and otherwise prints a canned leak
// report (already redacted, as the real tool does under --redact) to
// stdout, a diagnostic line to stderr, and exits 1 (leaks found).
func fakeGitleaks(t *testing.T) string {
	t.Helper()

	script := `#!/bin/sh
if [ "$1" = "version" ]; then
  echo "8.30.1-fake"
  exit 0
fi
cat <<'EOF'
[{"RuleID":"github-pat","Description":"Uncovered a GitHub Personal Access Token","StartLine":1,"EndLine":1,"Match":"REDACTED","Secret":"REDACTED","File":"config.py","Fingerprint":"config.py:github-pat:1"}]
EOF
echo "leaks found: 1" >&2
exit 1
`
	path := filepath.Join(t.TempDir(), "gitleaks")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestName(t *testing.T) {
	if got := New().Name(); got != "gitleaks" {
		t.Errorf("Name() = %q, want %q", got, "gitleaks")
	}
}

func TestVersionUsesFakeBinary(t *testing.T) {
	p := &Plugin{bin: fakeGitleaks(t)}
	if got := p.Version(); got != "8.30.1-fake" {
		t.Errorf("Version() = %q, want %q", got, "8.30.1-fake")
	}
}

func TestVersionMissingBinary(t *testing.T) {
	p := &Plugin{bin: "gitleaks-does-not-exist-xyz"}
	if got := p.Version(); got != "unknown" {
		t.Errorf("Version() = %q, want %q", got, "unknown")
	}
}

func TestHealthCheckPresent(t *testing.T) {
	p := &Plugin{bin: fakeGitleaks(t)}
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck returned error: %v", err)
	}
}

func TestHealthCheckMissing(t *testing.T) {
	p := &Plugin{bin: "gitleaks-does-not-exist-xyz"}
	if err := p.HealthCheck(context.Background()); err == nil {
		t.Error("HealthCheck should error when the binary isn't on PATH")
	}
}

func TestRunPassesRedactFlag(t *testing.T) {
	// The fake binary can't inspect its own flags, so check the command
	// construction the cheap-and-honest way: capture the args the fake
	// script received.
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args.txt")
	script := "#!/bin/sh\necho \"$@\" > " + argsFile + "\necho '[]'\nexit 0\n"
	bin := filepath.Join(dir, "gitleaks")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	p := &Plugin{bin: bin}
	if _, err := p.Run(context.Background(), "./target"); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "--redact") {
		t.Errorf("gitleaks invoked without --redact; args were: %s", args)
	}
}

func TestRunAndParseEndToEnd(t *testing.T) {
	p := &Plugin{bin: fakeGitleaks(t)}

	raw, err := p.Run(context.Background(), "./testdata")
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if raw.ExitCode != 1 {
		t.Errorf("RawResult.ExitCode = %d, want 1 (leaks found)", raw.ExitCode)
	}

	findings, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.Scanner != "gitleaks" {
		t.Errorf("Finding.Scanner = %q, want %q", f.Scanner, "gitleaks")
	}
	if f.RuleID != "github-pat" {
		t.Errorf("Finding.RuleID = %q, want %q", f.RuleID, "github-pat")
	}
	if f.ID != "config.py:github-pat:1" {
		t.Errorf("Finding.ID = %q, want the gitleaks fingerprint", f.ID)
	}
	if f.Severity != plugin.SeverityHigh {
		t.Errorf("Finding.Severity = %q, want %q", f.Severity, plugin.SeverityHigh)
	}
	if f.Location.Path != "config.py" || f.Location.StartLine != 1 {
		t.Errorf("Finding.Location = %+v, want Path=config.py StartLine=1", f.Location)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-798" {
		t.Errorf("Finding.CWE = %v, want [CWE-798]", f.CWE)
	}
}

func TestParseNeverCarriesSecretValues(t *testing.T) {
	// Even if the JSON somehow contains an unredacted secret (e.g. an
	// operator ran the tool by hand and fed the output in), Parse must
	// not copy it into any Finding field.
	p := New()
	// This value is hand-fed to Parse() directly, never through the
	// real gitleaks binary or scanned by anything — it doesn't need to
	// match a real provider's token format, so it's kept unambiguously
	// non-credential-shaped on purpose.
	leaked := "not-a-real-secret-value-for-redaction-test-only"
	raw := plugin.RawResult{
		ExitCode: 1,
		Output:   []byte(`[{"RuleID":"github-pat","Description":"desc","StartLine":1,"EndLine":1,"Match":"` + leaked + `","Secret":"` + leaked + `","File":"config.py","Fingerprint":"config.py:github-pat:1"}]`),
	}

	findings, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	f := findings[0]
	for name, val := range map[string]string{
		"ID": f.ID, "Title": f.Title, "Description": f.Description,
	} {
		if strings.Contains(val, leaked) {
			t.Errorf("Finding.%s contains the raw secret value", name)
		}
	}
	for k, v := range f.Metadata {
		if strings.Contains(v, leaked) {
			t.Errorf("Finding.Metadata[%q] contains the raw secret value", k)
		}
	}
}

func TestParseNoLeaks(t *testing.T) {
	p := New()
	raw := plugin.RawResult{ExitCode: 0, Output: []byte(`[]`)}

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
	raw := plugin.RawResult{ExitCode: 126, Stderr: []byte("FTL invalid config")}

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

var _ plugin.Scanner = New()
