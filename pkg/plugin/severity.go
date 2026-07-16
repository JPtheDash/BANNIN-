package plugin

import "sort"

// severityRank orders severities for sorting and threshold comparisons.
// Higher is more severe. Unknown severities rank below SeverityInfo so
// malformed data can never outrank a real finding.
var severityRank = map[Severity]int{
	SeverityCritical: 5,
	SeverityHigh:     4,
	SeverityMedium:   3,
	SeverityLow:      2,
	SeverityInfo:     1,
}

// Rank returns the severity's ordering weight: higher means more
// severe, 0 means unrecognized. Consumers (sorting, policy thresholds)
// should compare ranks rather than string values.
func (s Severity) Rank() int {
	return severityRank[s]
}

// IsValid reports whether s is one of the five normalized severities.
func (s Severity) IsValid() bool {
	return s.Rank() > 0
}

// NormalizeSeverity clamps arbitrary severity input to the five
// normalized values. Anything unrecognized (including empty) becomes
// SeverityMedium: the pipeline can't know how bad an unlabeled finding
// is, and both hiding it (info) and inflating it (critical) would
// misrepresent that uncertainty. This matches the defaulting the
// built-in plugins already apply.
func NormalizeSeverity(s Severity) Severity {
	if s.IsValid() {
		return s
	}
	return SeverityMedium
}

// NormalizeFindings normalizes every finding's severity in place (see
// NormalizeSeverity) and returns the slice for chaining.
func NormalizeFindings(findings []Finding) []Finding {
	for i := range findings {
		findings[i].Severity = NormalizeSeverity(findings[i].Severity)
	}
	return findings
}

// SortFindings orders findings most-severe first, in place. Ties are
// broken by scanner, path, start line, then rule ID, so output is
// deterministic across runs regardless of plugin execution order.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Scanner != b.Scanner {
			return a.Scanner < b.Scanner
		}
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		return a.RuleID < b.RuleID
	})
}
