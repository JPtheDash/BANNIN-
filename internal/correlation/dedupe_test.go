package correlation_test

import (
	"testing"

	"github.com/jyotidash/bannin/internal/correlation"
	"github.com/jyotidash/bannin/pkg/plugin"
)

func TestDedupeCollapsesExactDuplicates(t *testing.T) {
	dup := plugin.Finding{
		Scanner: "trivy", RuleID: "CVE-2026-1",
		Location: plugin.Location{Path: "go.mod"},
		Metadata: map[string]string{"package": "golang.org/x/sys", "version": "0.29.0"},
	}
	dupFromOtherScanner := dup
	dupFromOtherScanner.Scanner = "other-cve-scanner"

	got := correlation.Dedupe([]plugin.Finding{dup, dupFromOtherScanner})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1 (same CVE, path, and package should collapse)", len(got))
	}
	if got[0].Scanner != "trivy" {
		t.Errorf("kept finding from %q, want first occurrence (trivy)", got[0].Scanner)
	}
}

func TestDedupeKeepsSameRuleDifferentLocations(t *testing.T) {
	a := plugin.Finding{RuleID: "eval-detected", Location: plugin.Location{Path: "app.py", StartLine: 10, EndLine: 10}}
	b := plugin.Finding{RuleID: "eval-detected", Location: plugin.Location{Path: "app.py", StartLine: 20, EndLine: 20}}
	c := plugin.Finding{RuleID: "eval-detected", Location: plugin.Location{Path: "other.py", StartLine: 10, EndLine: 10}}

	got := correlation.Dedupe([]plugin.Finding{a, b, c})
	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3 (same rule at different locations is not a duplicate)", len(got))
	}
}

func TestDedupeKeepsSameCVEDifferentPackages(t *testing.T) {
	// One CVE can genuinely affect two packages listed in the same
	// manifest file (identical path, no line info) — those must survive.
	a := plugin.Finding{RuleID: "CVE-2026-9", Location: plugin.Location{Path: "go.mod"},
		Metadata: map[string]string{"package": "pkg-a", "version": "1.0.0"}}
	b := plugin.Finding{RuleID: "CVE-2026-9", Location: plugin.Location{Path: "go.mod"},
		Metadata: map[string]string{"package": "pkg-b", "version": "2.0.0"}}

	got := correlation.Dedupe([]plugin.Finding{a, b})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (same CVE in different packages is not a duplicate)", len(got))
	}
}

func TestDedupeDoesNotMergeDifferentRuleIDs(t *testing.T) {
	// OSV and Trivy report the same upstream advisory under different
	// identifiers (GO-XXXX vs CVE-XXXX). Alias reconciliation is future
	// correlation work; today both must survive.
	osv := plugin.Finding{Scanner: "osv", RuleID: "GO-2026-5024", Location: plugin.Location{Path: "go.mod"},
		Metadata: map[string]string{"package": "golang.org/x/sys", "version": "0.29.0"}}
	trivy := plugin.Finding{Scanner: "trivy", RuleID: "CVE-2026-39824", Location: plugin.Location{Path: "go.mod"},
		Metadata: map[string]string{"package": "golang.org/x/sys", "version": "0.29.0"}}

	got := correlation.Dedupe([]plugin.Finding{osv, trivy})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (different rule IDs must not be merged)", len(got))
	}
}

func TestDedupeEmptyAndNil(t *testing.T) {
	if got := correlation.Dedupe(nil); len(got) != 0 {
		t.Errorf("Dedupe(nil) returned %d findings, want 0", len(got))
	}
	if got := correlation.Dedupe([]plugin.Finding{}); len(got) != 0 {
		t.Errorf("Dedupe(empty) returned %d findings, want 0", len(got))
	}
}
