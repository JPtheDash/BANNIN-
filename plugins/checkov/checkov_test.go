package checkov

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// fakeCheckov writes a stand-in "checkov" executable to a temp dir and
// returns its path. It answers "--version" and otherwise prints the
// single-report JSON shape with one failed Dockerfile check, exiting 1
// (Checkov's "failed checks found" code).
func fakeCheckov(t *testing.T) string {
	t.Helper()

	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "3.3.0-fake"
  exit 0
fi
cat <<'EOF'
{"check_type":"dockerfile","results":{"failed_checks":[{"check_id":"CKV_DOCKER_7","check_name":"Ensure the base image uses a non latest version tag","file_path":"/Dockerfile","file_line_range":[3,3],"severity":null,"guideline":"https://example.com/ckv-docker-7","resource":"/Dockerfile.FROM"}]}}
EOF
exit 1
`
	path := filepath.Join(t.TempDir(), "checkov")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestName(t *testing.T) {
	if got := New().Name(); got != "checkov" {
		t.Errorf("Name() = %q, want %q", got, "checkov")
	}
}

func TestVersionUsesFakeBinary(t *testing.T) {
	p := &Plugin{bin: fakeCheckov(t)}
	if got := p.Version(); got != "3.3.0-fake" {
		t.Errorf("Version() = %q, want %q", got, "3.3.0-fake")
	}
}

func TestHealthCheckMissing(t *testing.T) {
	p := &Plugin{bin: "checkov-does-not-exist-xyz"}
	if err := p.HealthCheck(context.Background()); err == nil {
		t.Error("HealthCheck should error when the binary isn't on PATH")
	}
}

func TestRunAndParseEndToEnd(t *testing.T) {
	p := &Plugin{bin: fakeCheckov(t)}

	raw, err := p.Run(context.Background(), "./testdata")
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if raw.ExitCode != 1 {
		t.Errorf("RawResult.ExitCode = %d, want 1 (failed checks)", raw.ExitCode)
	}

	findings, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "CKV_DOCKER_7" {
		t.Errorf("Finding.RuleID = %q, want the check id", f.RuleID)
	}
	if f.Severity != plugin.SeverityMedium {
		t.Errorf("Finding.Severity = %q, want %q (null severity defaults to medium)", f.Severity, plugin.SeverityMedium)
	}
	if f.Location.Path != "Dockerfile" {
		t.Errorf("Finding.Location.Path = %q, want leading slash trimmed to %q", f.Location.Path, "Dockerfile")
	}
	if f.Location.StartLine != 3 || f.Location.EndLine != 3 {
		t.Errorf("Finding.Location lines = %d-%d, want 3-3", f.Location.StartLine, f.Location.EndLine)
	}
	if f.Metadata["check_type"] != "dockerfile" || f.Metadata["resource"] != "/Dockerfile.FROM" {
		t.Errorf("Finding.Metadata = %v, want check_type and resource set", f.Metadata)
	}
	if len(f.References) != 1 || !strings.Contains(f.References[0], "ckv-docker-7") {
		t.Errorf("Finding.References = %v, want the guideline URL", f.References)
	}
}

func TestParseArrayOutputMultipleFrameworks(t *testing.T) {
	// With several frameworks matched (terraform + dockerfile), Checkov
	// emits a JSON array of reports instead of a single object.
	p := New()
	raw := plugin.RawResult{
		ExitCode: 1,
		Output: []byte(`[
			{"check_type":"terraform","results":{"failed_checks":[{"check_id":"CKV_AWS_1","check_name":"tf check","file_path":"/main.tf","file_line_range":[1,3],"severity":null}]}},
			{"check_type":"dockerfile","results":{"failed_checks":[{"check_id":"CKV_DOCKER_2","check_name":"docker check","file_path":"/Dockerfile","file_line_range":[1,1],"severity":"HIGH"}]}}
		]`),
	}

	findings, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 across frameworks", len(findings))
	}
	if findings[0].Metadata["check_type"] != "terraform" || findings[1].Metadata["check_type"] != "dockerfile" {
		t.Errorf("check_type metadata wrong: %v / %v", findings[0].Metadata, findings[1].Metadata)
	}
	if findings[1].Severity != plugin.SeverityHigh {
		t.Errorf("explicit HIGH severity mapped to %q", findings[1].Severity)
	}
}

func TestParseBareSummaryNothingScanned(t *testing.T) {
	// A run over a directory with nothing scannable emits a bare summary
	// object with no check_type/results keys and exits 0.
	p := New()
	raw := plugin.RawResult{
		ExitCode: 0,
		Output:   []byte(`{"passed":0,"failed":0,"skipped":0,"parsing_errors":0,"resource_count":0,"checkov_version":"3.3.0"}`),
	}

	findings, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings from a nothing-scanned run, want 0", len(findings))
	}
}

func TestParseRejectsGenuineFailureExitCode(t *testing.T) {
	p := New()
	raw := plugin.RawResult{ExitCode: 2, Stderr: []byte("checkov crashed")}

	if _, err := p.Parse(raw); err == nil {
		t.Fatal("Parse should reject an exit code other than 0 or 1")
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
