package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// summaryOrder fixes the severity rows' display order, most severe
// first. Severities with zero findings are skipped.
var summaryOrder = []plugin.Severity{
	plugin.SeverityCritical,
	plugin.SeverityHigh,
	plugin.SeverityMedium,
	plugin.SeverityLow,
	plugin.SeverityInfo,
}

// Summary writes a human-readable digest of the report to w: total
// findings, the per-severity breakdown, and the per-scanner breakdown.
// It reports on findings only — plugin execution failures are the
// caller's to surface, since a Report never contains them.
func Summary(w io.Writer, r Report) {
	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "\nScan of %s complete: no findings.\n", r.Target)
		return
	}

	bySeverity := make(map[plugin.Severity]int)
	byScanner := make(map[string]int)
	for _, f := range r.Findings {
		bySeverity[f.Severity]++
		byScanner[f.Scanner]++
	}

	fmt.Fprintf(w, "\nScan of %s complete: %d findings\n\n", r.Target, len(r.Findings))

	fmt.Fprintln(w, "  By severity:")
	for _, sev := range summaryOrder {
		if n := bySeverity[sev]; n > 0 {
			fmt.Fprintf(w, "    %-8s %d\n", sev, n)
		}
	}

	// Findings arrive risk-ordered from New, so the head of the list is
	// the answer to "what should I fix first".
	fmt.Fprintln(w, "\n  Top risks:")
	for i, f := range r.Findings {
		if i == 3 {
			break
		}
		where := f.Location.Path
		if where == "" {
			where = f.Scanner
		}
		fmt.Fprintf(w, "    %3d  %s  (%s)\n", f.Risk.Score, f.Title, where)
	}

	fmt.Fprintln(w, "\n  By scanner:")
	scanners := make([]string, 0, len(byScanner))
	for name := range byScanner {
		scanners = append(scanners, name)
	}
	sort.Strings(scanners)
	for _, name := range scanners {
		fmt.Fprintf(w, "    %-8s %d\n", name, byScanner[name])
	}
}
