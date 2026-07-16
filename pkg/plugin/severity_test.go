package plugin_test

import (
	"testing"

	"github.com/jyotidash/bannin/pkg/plugin"
)

func TestSeverityRankOrdering(t *testing.T) {
	ordered := []plugin.Severity{
		plugin.SeverityCritical,
		plugin.SeverityHigh,
		plugin.SeverityMedium,
		plugin.SeverityLow,
		plugin.SeverityInfo,
	}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].Rank() <= ordered[i].Rank() {
			t.Errorf("Rank(%q) = %d should exceed Rank(%q) = %d",
				ordered[i-1], ordered[i-1].Rank(), ordered[i], ordered[i].Rank())
		}
	}
	if got := plugin.Severity("bogus").Rank(); got != 0 {
		t.Errorf("Rank of unknown severity = %d, want 0", got)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	if got := plugin.NormalizeSeverity(plugin.SeverityCritical); got != plugin.SeverityCritical {
		t.Errorf("NormalizeSeverity(critical) = %q, want critical unchanged", got)
	}
	for _, s := range []plugin.Severity{"", "BOGUS", "moderate"} {
		if got := plugin.NormalizeSeverity(s); got != plugin.SeverityMedium {
			t.Errorf("NormalizeSeverity(%q) = %q, want medium", s, got)
		}
	}
}

func TestNormalizeFindings(t *testing.T) {
	findings := []plugin.Finding{
		{ID: "a", Severity: plugin.SeverityHigh},
		{ID: "b", Severity: ""},
		{ID: "c", Severity: "WEIRD"},
	}
	plugin.NormalizeFindings(findings)

	want := []plugin.Severity{plugin.SeverityHigh, plugin.SeverityMedium, plugin.SeverityMedium}
	for i, f := range findings {
		if f.Severity != want[i] {
			t.Errorf("finding %q severity = %q, want %q", f.ID, f.Severity, want[i])
		}
	}
}

func TestSortFindings(t *testing.T) {
	findings := []plugin.Finding{
		{ID: "low", Severity: plugin.SeverityLow, Scanner: "a"},
		{ID: "crit", Severity: plugin.SeverityCritical, Scanner: "z"},
		{ID: "med-b", Severity: plugin.SeverityMedium, Scanner: "b", Location: plugin.Location{Path: "x.go", StartLine: 5}},
		{ID: "med-a", Severity: plugin.SeverityMedium, Scanner: "b", Location: plugin.Location{Path: "x.go", StartLine: 2}},
		{ID: "high", Severity: plugin.SeverityHigh, Scanner: "a"},
	}
	plugin.SortFindings(findings)

	wantOrder := []string{"crit", "high", "med-a", "med-b", "low"}
	for i, want := range wantOrder {
		if findings[i].ID != want {
			t.Fatalf("position %d = %q, want %q (full order: %v)", i, findings[i].ID, want, ids(findings))
		}
	}
}

func TestSortFindingsDeterministicAcrossInputOrder(t *testing.T) {
	base := []plugin.Finding{
		{ID: "1", Severity: plugin.SeverityHigh, Scanner: "osv", RuleID: "CVE-1", Location: plugin.Location{Path: "go.mod"}},
		{ID: "2", Severity: plugin.SeverityHigh, Scanner: "trivy", RuleID: "CVE-1", Location: plugin.Location{Path: "go.mod"}},
		{ID: "3", Severity: plugin.SeverityHigh, Scanner: "osv", RuleID: "CVE-2", Location: plugin.Location{Path: "go.mod"}},
	}
	reversed := []plugin.Finding{base[2], base[1], base[0]}

	plugin.SortFindings(base)
	plugin.SortFindings(reversed)

	for i := range base {
		if base[i].ID != reversed[i].ID {
			t.Fatalf("sort is input-order dependent: %v vs %v", ids(base), ids(reversed))
		}
	}
}

func ids(findings []plugin.Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.ID
	}
	return out
}
