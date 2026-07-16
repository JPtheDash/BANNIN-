package dashboard_test

import (
	"testing"

	"github.com/jyotidash/bannin/internal/dashboard"
	"github.com/jyotidash/bannin/internal/report"
	"github.com/jyotidash/bannin/pkg/plugin"
)

func TestSummarize(t *testing.T) {
	findings := []plugin.Finding{
		{ID: "1", Scanner: "gitleaks", RuleID: "aws-key", Title: "secret", Severity: plugin.SeverityHigh,
			Location: plugin.Location{Path: ".env"}},
		{ID: "2", Scanner: "semgrep", RuleID: "eval", Title: "eval", Severity: plugin.SeverityHigh,
			Location: plugin.Location{Path: "app.py"}},
		{ID: "3", Scanner: "osv", RuleID: "GO-1", Title: "vuln", Severity: plugin.SeverityMedium,
			Location: plugin.Location{Path: "go.mod"}},
	}
	r := report.New("./demo", []string{"gitleaks", "semgrep", "osv"}, findings)

	s := dashboard.Summarize(r)

	if s.Target != "./demo" || s.Total != 3 {
		t.Errorf("Summary target/total = %q/%d, want ./demo/3", s.Target, s.Total)
	}
	if s.BySeverity[plugin.SeverityHigh] != 2 || s.BySeverity[plugin.SeverityMedium] != 1 {
		t.Errorf("BySeverity = %v, want high:2 medium:1", s.BySeverity)
	}
	if s.ByScanner["gitleaks"] != 1 || s.ByScanner["semgrep"] != 1 || s.ByScanner["osv"] != 1 {
		t.Errorf("ByScanner = %v, want one each", s.ByScanner)
	}
	if len(s.TopRisks) != 3 {
		t.Fatalf("TopRisks has %d entries, want all 3 (under the cap)", len(s.TopRisks))
	}
	// gitleaks' exposed-secret factor should outscore the plain semgrep high.
	if s.TopRisks[0].Scanner != "gitleaks" {
		t.Errorf("TopRisks[0].Scanner = %q, want the highest-risk finding first (gitleaks)", s.TopRisks[0].Scanner)
	}
}

func TestSummarizeCapsTopRisks(t *testing.T) {
	var findings []plugin.Finding
	for i := 0; i < 15; i++ {
		findings = append(findings, plugin.Finding{
			ID: string(rune('a' + i)), Scanner: "semgrep", RuleID: "r", Title: "t",
			Severity: plugin.SeverityHigh, Location: plugin.Location{Path: "f.py"},
		})
	}
	s := dashboard.Summarize(report.New(".", nil, findings))

	if s.Total != 15 {
		t.Errorf("Total = %d, want 15", s.Total)
	}
	if len(s.TopRisks) != 10 {
		t.Errorf("len(TopRisks) = %d, want capped at 10", len(s.TopRisks))
	}
}

func TestSummarizeEmptyReport(t *testing.T) {
	s := dashboard.Summarize(report.New(".", nil, nil))

	if s.Total != 0 || len(s.TopRisks) != 0 {
		t.Errorf("Summary of an empty report = %+v, want zero values", s)
	}
}
