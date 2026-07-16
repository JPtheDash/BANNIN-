package risk_test

import (
	"testing"

	"github.com/jyotidash/bannin/internal/risk"
	"github.com/jyotidash/bannin/pkg/plugin"
)

func TestAssessSeverityBaseline(t *testing.T) {
	cases := []struct {
		sev  plugin.Severity
		want int
	}{
		{plugin.SeverityCritical, 90},
		{plugin.SeverityHigh, 70},
		{plugin.SeverityMedium, 50},
		{plugin.SeverityLow, 30},
		{plugin.SeverityInfo, 10},
		{"bogus", 50}, // defensively re-normalized to medium
	}
	for _, c := range cases {
		got := risk.Assess(plugin.Finding{Scanner: "semgrep", Severity: c.sev, Location: plugin.Location{Path: "app.py"}})
		if got.Score != c.want {
			t.Errorf("Assess(%s).Score = %d, want %d (baseline only)", c.sev, got.Score, c.want)
		}
	}
}

func TestAssessModifiers(t *testing.T) {
	cases := []struct {
		name       string
		f          plugin.Finding
		want       int
		wantFactor string
	}{
		{
			"corroborated advisory",
			plugin.Finding{Scanner: "osv", Severity: plugin.SeverityHigh,
				Location: plugin.Location{Path: "requirements.txt"},
				Metadata: map[string]string{"also_reported_by": "trivy"}},
			80, "corroborated",
		},
		{
			"exposed secret",
			plugin.Finding{Scanner: "gitleaks", Severity: plugin.SeverityHigh,
				Location: plugin.Location{Path: ".env"}},
			85, "exposed-secret",
		},
		{
			"runtime-confirmed DAST finding",
			plugin.Finding{Scanner: "zap", Severity: plugin.SeverityMedium,
				Location: plugin.Location{Path: "http://127.0.0.1:5000/login"}},
			60, "runtime-confirmed",
		},
		{
			"fix available",
			plugin.Finding{Scanner: "trivy", Severity: plugin.SeverityHigh,
				Location: plugin.Location{Path: "go.mod"},
				Metadata: map[string]string{"fixed_version": "1.2.3"}},
			75, "fix-available",
		},
		{
			"non-production path",
			plugin.Finding{Scanner: "semgrep", Severity: plugin.SeverityHigh,
				Location: plugin.Location{Path: "pkg/tests/helper.py"}},
			55, "non-production-path",
		},
	}
	for _, c := range cases {
		got := risk.Assess(c.f)
		if got.Score != c.want {
			t.Errorf("%s: Score = %d, want %d (factors: %+v)", c.name, got.Score, c.want, got.Factors)
		}
		found := false
		for _, fa := range got.Factors {
			if fa.Name == c.wantFactor {
				found = true
				if fa.Reason == "" {
					t.Errorf("%s: factor %q has no reason — every factor must be explainable", c.name, fa.Name)
				}
			}
		}
		if !found {
			t.Errorf("%s: factor %q missing from %+v", c.name, c.wantFactor, got.Factors)
		}
	}
}

func TestAssessSegmentMatchIsWholeSegment(t *testing.T) {
	// "demo-app" and "contest" contain test/example-ish substrings but
	// are not test dirs; only whole segments may dampen.
	for _, path := range []string{"examples-notes/app.py", "demo-app/main.py", "contest/entry.py"} {
		got := risk.Assess(plugin.Finding{Scanner: "semgrep", Severity: plugin.SeverityHigh,
			Location: plugin.Location{Path: path}})
		if got.Score != 70 {
			t.Errorf("path %q: Score = %d, want 70 (no dampening for partial segment matches)", path, got.Score)
		}
	}
	got := risk.Assess(plugin.Finding{Scanner: "semgrep", Severity: plugin.SeverityHigh,
		Location: plugin.Location{Path: "examples/demo-app/app.py"}})
	if got.Score != 55 {
		t.Errorf("examples/ path: Score = %d, want 55 (dampened)", got.Score)
	}
}

func TestAssessClamps(t *testing.T) {
	// critical + corroborated + secret would exceed 100.
	high := risk.Assess(plugin.Finding{Scanner: "gitleaks", Severity: plugin.SeverityCritical,
		Location: plugin.Location{Path: ".env"},
		Metadata: map[string]string{"also_reported_by": "semgrep"}})
	if high.Score != 100 {
		t.Errorf("Score = %d, want clamped to 100", high.Score)
	}

	// info in test code would go negative.
	low := risk.Assess(plugin.Finding{Scanner: "semgrep", Severity: plugin.SeverityInfo,
		Location: plugin.Location{Path: "tests/x.py"}})
	if low.Score != 0 {
		t.Errorf("Score = %d, want clamped to 0", low.Score)
	}
}

func TestAssessScoreEqualsFactorSumWhenUnclamped(t *testing.T) {
	got := risk.Assess(plugin.Finding{Scanner: "trivy", Severity: plugin.SeverityHigh,
		Location: plugin.Location{Path: "go.mod"},
		Metadata: map[string]string{"fixed_version": "2.0", "also_reported_by": "osv"}})
	sum := 0
	for _, fa := range got.Factors {
		sum += fa.Delta
	}
	if got.Score != sum {
		t.Errorf("Score = %d but factors sum to %d — the score must be fully attributable", got.Score, sum)
	}
}
