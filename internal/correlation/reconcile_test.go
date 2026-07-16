package correlation

import (
	"reflect"
	"testing"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// advisory builds a dependency-style finding the way plugins/osv and
// plugins/trivy do.
func advisory(scanner, ruleID string, aliases []string, sev plugin.Severity, path, pkg, version string) plugin.Finding {
	return plugin.Finding{
		ID:       ruleID + ":" + pkg + "@" + version,
		Scanner:  scanner,
		RuleID:   ruleID,
		Aliases:  aliases,
		Severity: sev,
		Location: plugin.Location{Path: path},
		Metadata: map[string]string{"package": pkg, "version": version},
	}
}

// The real-world shape this exists for: OSV reports one flask bug twice
// (PYSEC and GHSA entries, mutual aliases) and Trivy adds the CVE with
// no alias list of its own. All three must collapse — transitively,
// since the CVE only links to the others through their alias lists.
func TestReconcileAliasesMergesAcrossSchemes(t *testing.T) {
	findings := []plugin.Finding{
		advisory("osv", "PYSEC-2018-66", []string{"CVE-2018-1000656", "GHSA-562c-5r94-xh97"},
			plugin.SeverityMedium, "requirements.txt", "flask", "0.12.2"),
		advisory("osv", "GHSA-562c-5r94-xh97", []string{"CVE-2018-1000656", "PYSEC-2018-66"},
			plugin.SeverityMedium, "requirements.txt", "flask", "0.12.2"),
		advisory("trivy", "CVE-2018-1000656", nil,
			plugin.SeverityHigh, "requirements.txt", "flask", "0.12.2"),
	}
	findings[2].References = []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-1000656"}
	findings[0].References = []string{"https://osv.dev/PYSEC-2018-66"}

	out := ReconcileAliases(findings)

	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1 merged", len(out))
	}
	f := out[0]
	if f.RuleID != "CVE-2018-1000656" || f.Scanner != "trivy" {
		t.Errorf("merged base = %s from %s, want the most severe member (trivy's high CVE)", f.RuleID, f.Scanner)
	}
	if f.Severity != plugin.SeverityHigh {
		t.Errorf("Severity = %q, want the max across the cluster (%q)", f.Severity, plugin.SeverityHigh)
	}
	wantAliases := []string{"GHSA-562c-5r94-xh97", "PYSEC-2018-66"}
	if !reflect.DeepEqual(f.Aliases, wantAliases) {
		t.Errorf("Aliases = %v, want %v (all other ids, sorted)", f.Aliases, wantAliases)
	}
	wantRefs := []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-1000656", "https://osv.dev/PYSEC-2018-66"}
	if !reflect.DeepEqual(f.References, wantRefs) {
		t.Errorf("References = %v, want union %v", f.References, wantRefs)
	}
	if f.Metadata["also_reported_by"] != "osv" {
		t.Errorf(`Metadata["also_reported_by"] = %q, want "osv"`, f.Metadata["also_reported_by"])
	}
}

func TestReconcileAliasesDoesNotMutateBaseMetadata(t *testing.T) {
	findings := []plugin.Finding{
		advisory("trivy", "CVE-1", nil, plugin.SeverityHigh, "go.mod", "foo", "1.0"),
		advisory("osv", "GO-1", []string{"CVE-1"}, plugin.SeverityLow, "go.mod", "foo", "1.0"),
	}
	baseMeta := findings[0].Metadata

	ReconcileAliases(findings)

	if _, leaked := baseMeta["also_reported_by"]; leaked {
		t.Error("merge wrote also_reported_by into the original finding's Metadata map")
	}
}

func TestReconcileAliasesRequiresSharedIdentifier(t *testing.T) {
	// Same package@version and path, but no identifier overlap: two
	// genuinely distinct advisories against one dependency.
	findings := []plugin.Finding{
		advisory("osv", "PYSEC-2019-179", []string{"CVE-2019-1010083"}, plugin.SeverityMedium, "requirements.txt", "flask", "0.12.2"),
		advisory("osv", "PYSEC-2023-62", []string{"CVE-2023-30861"}, plugin.SeverityMedium, "requirements.txt", "flask", "0.12.2"),
	}

	if out := ReconcileAliases(findings); len(out) != 2 {
		t.Errorf("got %d findings, want 2: distinct advisories must not merge", len(out))
	}
}

func TestReconcileAliasesRequiresSamePackageAndPath(t *testing.T) {
	cases := []struct {
		name string
		a, b plugin.Finding
	}{
		{
			"different package versions",
			advisory("osv", "GHSA-x", []string{"CVE-1"}, plugin.SeverityHigh, "go.mod", "foo", "1.0"),
			advisory("trivy", "CVE-1", nil, plugin.SeverityHigh, "go.mod", "foo", "2.0"),
		},
		{
			"different lockfiles",
			advisory("osv", "GHSA-x", []string{"CVE-1"}, plugin.SeverityHigh, "a/go.mod", "foo", "1.0"),
			advisory("trivy", "CVE-1", nil, plugin.SeverityHigh, "b/go.mod", "foo", "1.0"),
		},
	}
	for _, c := range cases {
		if out := ReconcileAliases([]plugin.Finding{c.a, c.b}); len(out) != 2 {
			t.Errorf("%s: got %d findings, want 2 (no merge)", c.name, len(out))
		}
	}
}

func TestReconcileAliasesIgnoresNonAdvisoryFindings(t *testing.T) {
	// SAST/secrets/IaC findings carry no package metadata and must pass
	// through untouched even when rule IDs collide.
	findings := []plugin.Finding{
		{ID: "1", Scanner: "semgrep", RuleID: "python.lang.security.audit.eval", Severity: plugin.SeverityHigh, Location: plugin.Location{Path: "app.py", StartLine: 3}},
		{ID: "2", Scanner: "semgrep", RuleID: "python.lang.security.audit.eval", Severity: plugin.SeverityHigh, Location: plugin.Location{Path: "app.py", StartLine: 9}},
	}

	if out := ReconcileAliases(findings); len(out) != 2 {
		t.Errorf("got %d findings, want 2: non-advisory findings must never merge", len(out))
	}
}

func TestReconcileAliasesPreservesOrderAndOtherFindings(t *testing.T) {
	findings := []plugin.Finding{
		{ID: "sast", Scanner: "semgrep", RuleID: "rule-a", Severity: plugin.SeverityCritical, Location: plugin.Location{Path: "app.py"}},
		advisory("osv", "GO-1", []string{"CVE-1"}, plugin.SeverityHigh, "go.mod", "foo", "1.0"),
		{ID: "secret", Scanner: "gitleaks", RuleID: "aws-key", Severity: plugin.SeverityHigh, Location: plugin.Location{Path: ".env"}},
		advisory("trivy", "CVE-1", nil, plugin.SeverityLow, "go.mod", "foo", "1.0"),
	}

	out := ReconcileAliases(findings)

	wantIDs := []string{"sast", "GO-1:foo@1.0", "secret"}
	if len(out) != len(wantIDs) {
		t.Fatalf("got %d findings, want %d", len(out), len(wantIDs))
	}
	for i, want := range wantIDs {
		if out[i].ID != want {
			t.Errorf("out[%d].ID = %q, want %q (merged finding sits at the cluster's first position)", i, out[i].ID, want)
		}
	}
	// Base is the higher-severity OSV finding; trivy's id becomes an alias.
	if got := out[1].Aliases; len(got) != 1 || got[0] != "CVE-1" {
		t.Errorf("merged Aliases = %v, want [CVE-1]", got)
	}
	if out[1].Metadata["also_reported_by"] != "trivy" {
		t.Errorf(`also_reported_by = %q, want "trivy"`, out[1].Metadata["also_reported_by"])
	}
}

func TestReconcileAliasesEmptyInput(t *testing.T) {
	if out := ReconcileAliases(nil); len(out) != 0 {
		t.Errorf("got %d findings for nil input, want 0", len(out))
	}
}
