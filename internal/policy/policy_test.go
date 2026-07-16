package policy_test

import (
	"testing"

	"github.com/jyotidash/bannin/internal/policy"
	"github.com/jyotidash/bannin/pkg/plugin"
)

func findingsWith(sevs ...plugin.Severity) []plugin.Finding {
	out := make([]plugin.Finding, len(sevs))
	for i, s := range sevs {
		out[i] = plugin.Finding{ID: string(s), Severity: s}
	}
	return out
}

func TestEvaluateFailsAtOrAboveThreshold(t *testing.T) {
	findings := findingsWith(
		plugin.SeverityCritical,
		plugin.SeverityHigh,
		plugin.SeverityMedium,
		plugin.SeverityLow,
		plugin.SeverityInfo,
	)

	cases := []struct {
		failOn         plugin.Severity
		wantViolations int
	}{
		{plugin.SeverityCritical, 1},
		{plugin.SeverityHigh, 2},
		{plugin.SeverityMedium, 3},
		{plugin.SeverityLow, 4},
		{plugin.SeverityInfo, 5},
	}
	for _, c := range cases {
		d, err := policy.Evaluate(findings, c.failOn)
		if err != nil {
			t.Fatalf("Evaluate(failOn=%s) returned error: %v", c.failOn, err)
		}
		if len(d.Violations) != c.wantViolations {
			t.Errorf("failOn=%s: %d violations, want %d", c.failOn, len(d.Violations), c.wantViolations)
		}
		if d.Failed() != (c.wantViolations > 0) {
			t.Errorf("failOn=%s: Failed() = %v, inconsistent with %d violations", c.failOn, d.Failed(), c.wantViolations)
		}
		if d.Threshold != c.failOn {
			t.Errorf("Decision.Threshold = %q, want %q", d.Threshold, c.failOn)
		}
	}
}

func TestEvaluatePassesWhenAllFindingsBelowThreshold(t *testing.T) {
	findings := findingsWith(plugin.SeverityMedium, plugin.SeverityLow)

	d, err := policy.Evaluate(findings, plugin.SeverityHigh)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if d.Failed() {
		t.Errorf("gate failed with only medium/low findings against a high threshold: %+v", d.Violations)
	}
}

func TestEvaluateNoFindingsPasses(t *testing.T) {
	d, err := policy.Evaluate(nil, plugin.SeverityLow)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if d.Failed() {
		t.Error("gate failed with zero findings")
	}
}

func TestEvaluateRejectsInvalidThreshold(t *testing.T) {
	for _, bad := range []plugin.Severity{"", "bogus", "MODERATE"} {
		if _, err := policy.Evaluate(nil, bad); err == nil {
			t.Errorf("Evaluate accepted invalid threshold %q", bad)
		}
	}
}

func TestEvaluateViolationsCarryTheFindings(t *testing.T) {
	findings := findingsWith(plugin.SeverityCritical, plugin.SeverityLow)

	d, err := policy.Evaluate(findings, plugin.SeverityHigh)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if len(d.Violations) != 1 || d.Violations[0].Severity != plugin.SeverityCritical {
		t.Errorf("Violations = %+v, want just the critical finding", d.Violations)
	}
}
