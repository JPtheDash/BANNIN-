package policy

import (
	"fmt"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// Decision is the outcome of evaluating a scan's findings against a
// severity gate: the threshold applied and every finding at or above it.
type Decision struct {
	Threshold  plugin.Severity
	Violations []plugin.Finding
}

// Failed reports whether the gate was breached.
func (d Decision) Failed() bool { return len(d.Violations) > 0 }

// Evaluate applies the fail_on_severity gate: any finding whose severity
// ranks at or above failOn is a violation. Findings are expected to be
// already normalized (plugin.NormalizeFindings); an unrecognized
// threshold is an error rather than a guess, because a misconfigured
// gate silently passing (or failing) everything would defeat the point
// of gating.
func Evaluate(findings []plugin.Finding, failOn plugin.Severity) (Decision, error) {
	if !failOn.IsValid() {
		return Decision{}, fmt.Errorf("policy: invalid fail_on_severity %q", failOn)
	}

	d := Decision{Threshold: failOn}
	for _, f := range findings {
		if f.Severity.Rank() >= failOn.Rank() {
			d.Violations = append(d.Violations, f)
		}
	}
	return d, nil
}
