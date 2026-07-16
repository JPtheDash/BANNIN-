package report_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jyotidash/bannin/internal/report"
	"github.com/jyotidash/bannin/pkg/plugin"
)

func sampleFindings() []plugin.Finding {
	return []plugin.Finding{
		{ID: "1", Scanner: "semgrep", RuleID: "eval-detected", Title: "eval", Severity: plugin.SeverityHigh,
			Location: plugin.Location{Path: "app.py", StartLine: 10}},
		{ID: "2", Scanner: "gitleaks", RuleID: "github-pat", Title: "secret", Severity: plugin.SeverityHigh,
			Location: plugin.Location{Path: "config.py", StartLine: 1}},
		{ID: "3", Scanner: "osv", RuleID: "GO-1", Title: "vuln", Severity: plugin.SeverityMedium,
			Location: plugin.Location{Path: "go.mod"}},
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "out")
	r := report.New(".", []string{"semgrep", "osv", "gitleaks"}, sampleFindings())

	path, err := report.WriteJSON(dir, r)
	if err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}
	if filepath.Base(path) != "report.json" {
		t.Errorf("wrote %q, want a report.json", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got report.Report
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("written report is not valid JSON: %v", err)
	}
	if got.Target != "." || len(got.Findings) != 3 {
		t.Errorf("round-trip mismatch: target=%q findings=%d", got.Target, len(got.Findings))
	}
	// Findings are risk-ordered: the gitleaks secret (high + exposed-secret)
	// outscores the semgrep high, which outscores the osv medium.
	if got.Findings[0].RuleID != "github-pat" {
		t.Errorf("Findings[0].RuleID = %q, want the highest-risk finding (github-pat) first", got.Findings[0].RuleID)
	}
	for i := 1; i < len(got.Findings); i++ {
		if got.Findings[i-1].Risk.Score < got.Findings[i].Risk.Score {
			t.Errorf("findings not risk-ordered: score %d before %d", got.Findings[i-1].Risk.Score, got.Findings[i].Risk.Score)
		}
	}
	if f := got.Findings[0]; f.Risk.Score == 0 || len(f.Risk.Factors) == 0 {
		t.Errorf("risk assessment lost in round-trip: %+v", f.Risk)
	}
	if got.GeneratedAt.IsZero() {
		t.Error("generated_at missing from written report")
	}
}

func TestWriteJSONEmptyFindingsIsArrayNotNull(t *testing.T) {
	dir := t.TempDir()
	path, err := report.WriteJSON(dir, report.New(".", nil, nil))
	if err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"findings": null`) {
		t.Error("empty findings serialized as null, want []")
	}
}

func TestSummaryBreakdowns(t *testing.T) {
	buf := &bytes.Buffer{}
	report.Summary(buf, report.New("./examples/demo-app", nil, sampleFindings()))
	out := buf.String()

	for _, want := range []string{
		"3 findings",
		"./examples/demo-app",
		"high",
		"medium",
		"semgrep",
		"gitleaks",
		"osv",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q; full output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "critical") {
		t.Errorf("summary shows a severity with zero findings; full output:\n%s", out)
	}
}

func TestSummaryNoFindings(t *testing.T) {
	buf := &bytes.Buffer{}
	report.Summary(buf, report.New(".", nil, nil))
	if !strings.Contains(buf.String(), "no findings") {
		t.Errorf("empty-scan summary = %q, want a clear no-findings message", buf.String())
	}
}
