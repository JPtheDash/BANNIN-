package dashboard

import (
	"github.com/jyotidash/bannin/internal/report"
	"github.com/jyotidash/bannin/pkg/plugin"
)

// Summary is a lightweight aggregate view of a report, cheap enough to
// poll: total counts and a short risk-ordered highlights list, rather
// than the full findings collection GET /api/v1/report returns.
type Summary struct {
	Target      string                  `json:"target"`
	GeneratedAt string                  `json:"generated_at"`
	Total       int                     `json:"total"`
	BySeverity  map[plugin.Severity]int `json:"by_severity"`
	ByScanner   map[string]int          `json:"by_scanner"`
	TopRisks    []report.Finding        `json:"top_risks"`
}

// topRisksLimit caps how many findings Summarize includes under
// TopRisks — enough to be useful on a dashboard tile without repeating
// the full report.
const topRisksLimit = 10

// Summarize aggregates r into a Summary. r.Findings is expected
// risk-ordered (report.New guarantees this), so the head of the slice
// is already the highlights list.
func Summarize(r report.Report) Summary {
	bySeverity := make(map[plugin.Severity]int)
	byScanner := make(map[string]int)
	for _, f := range r.Findings {
		bySeverity[f.Severity]++
		byScanner[f.Scanner]++
	}

	top := r.Findings
	if len(top) > topRisksLimit {
		top = top[:topRisksLimit]
	}

	return Summary{
		Target:      r.Target,
		GeneratedAt: r.GeneratedAt.Format("2006-01-02T15:04:05Z07:00"),
		Total:       len(r.Findings),
		BySeverity:  bySeverity,
		ByScanner:   byScanner,
		TopRisks:    top,
	}
}
