package correlation

import (
	"strconv"
	"strings"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// Dedupe removes findings that are exact duplicates of one another,
// keeping the first occurrence and preserving input order otherwise.
//
// Two findings are duplicates when they share the same rule ID, file
// location, and affected package (from the package/version metadata the
// dependency-scanning plugins set). The rule ID must match literally, so
// this only collapses reports of the same identifier — e.g. the same CVE
// flagged twice, or one plugin run twice. The semantically-same advisory
// published under different IDs (OSV's GO-XXXX vs Trivy's CVE-XXXX for
// one upstream bug) is ReconcileAliases' job, which runs after this and
// merges only on documented alias links rather than guesswork.
func Dedupe(findings []plugin.Finding) []plugin.Finding {
	seen := make(map[string]bool, len(findings))
	out := findings[:0]
	for _, f := range findings {
		key := dedupeKey(f)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func dedupeKey(f plugin.Finding) string {
	return strings.Join([]string{
		f.RuleID,
		f.Location.Path,
		strconv.Itoa(f.Location.StartLine),
		strconv.Itoa(f.Location.EndLine),
		f.Metadata["package"],
		f.Metadata["version"],
	}, "\x1f")
}
