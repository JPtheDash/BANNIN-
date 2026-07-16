package risk

import (
	"fmt"
	"strings"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// Factor is one documented contribution to a risk score. Every point of
// a score is attributable to a named factor with a human-readable
// reason — a score the user can't audit is a score they can't trust.
type Factor struct {
	Name   string `json:"name"`
	Delta  int    `json:"delta"`
	Reason string `json:"reason"`
}

// Assessment is a finding's risk score (0–100) plus the factors that
// produced it. The score is the sum of the factor deltas, clamped.
type Assessment struct {
	Score   int      `json:"score"`
	Factors []Factor `json:"factors,omitempty"`
}

// severityBase anchors the score to the normalized severity. Modifiers
// adjust around it but can never turn an info finding into a critical
// one or vice versa — severity stays the dominant signal.
var severityBase = map[plugin.Severity]int{
	plugin.SeverityCritical: 90,
	plugin.SeverityHigh:     70,
	plugin.SeverityMedium:   50,
	plugin.SeverityLow:      30,
	plugin.SeverityInfo:     10,
}

// nonProductionSegments are path segments that usually mark code which
// doesn't ship: findings there are real but rarely the first thing to
// fix. Matched as whole segments so e.g. "demo-app" or "contest" never
// triggers a match.
var nonProductionSegments = map[string]bool{
	"test": true, "tests": true, "testdata": true,
	"spec": true, "specs": true, "fixtures": true,
	"example": true, "examples": true,
	"vendor": true, "node_modules": true, "third_party": true,
}

// Assess computes a finding's risk score from signals present in the
// normalized Finding itself. It is a prioritization aid layered on top
// of severity, not a vulnerability metric: it answers "which of these
// should I look at first", using only evidence the pipeline already
// carries — no reachability analysis, no exploit-intelligence feeds.
// Findings are expected severity-normalized (the pipeline guarantees
// it); Assess re-normalizes defensively.
func Assess(f plugin.Finding) Assessment {
	sev := plugin.NormalizeSeverity(f.Severity)
	factors := []Factor{{
		Name:   "severity",
		Delta:  severityBase[sev],
		Reason: string(sev) + " severity baseline",
	}}

	if by := f.Metadata["also_reported_by"]; by != "" {
		factors = append(factors, Factor{
			Name:   "corroborated",
			Delta:  10,
			Reason: "independently reported by " + by,
		})
	}
	// Scanner names are part of the stable plugin contract; gitleaks is
	// the secrets scanner. A leaked credential needs no exploit — it is
	// directly usable by anyone who reads the file.
	if f.Scanner == "gitleaks" {
		factors = append(factors, Factor{
			Name:   "exposed-secret",
			Delta:  15,
			Reason: "a leaked credential is directly usable, no exploit required",
		})
	}
	// A URL location means a dynamic scanner observed this on a running
	// application — reachability is proven, not assumed.
	if strings.HasPrefix(f.Location.Path, "http://") || strings.HasPrefix(f.Location.Path, "https://") {
		factors = append(factors, Factor{
			Name:   "runtime-confirmed",
			Delta:  10,
			Reason: "observed on a running application, so it is reachable",
		})
	}
	if v := f.Metadata["fixed_version"]; v != "" {
		factors = append(factors, Factor{
			Name:   "fix-available",
			Delta:  5,
			Reason: fmt.Sprintf("an upgrade path exists (fixed in %s)", v),
		})
	}
	if seg := nonProductionSegment(f.Location.Path); seg != "" {
		factors = append(factors, Factor{
			Name:   "non-production-path",
			Delta:  -15,
			Reason: fmt.Sprintf("located under a %q path segment, which usually doesn't ship", seg),
		})
	}

	score := 0
	for _, fa := range factors {
		score += fa.Delta
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return Assessment{Score: score, Factors: factors}
}

// nonProductionSegment returns the first path segment matching
// nonProductionSegments, or "".
func nonProductionSegment(path string) string {
	for _, seg := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if nonProductionSegments[seg] {
			return seg
		}
	}
	return ""
}
