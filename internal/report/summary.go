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

// categoryOrder fixes the category rows' display order — roughly
// "closest to shipping code" first: what a developer wrote (SAST),
// what they pulled in (SCA), what leaked (secrets), what it runs on
// (IaC), then what's observable once it's live (DAST).
var categoryOrder = []plugin.Category{
	plugin.CategorySAST,
	plugin.CategorySCA,
	plugin.CategorySecrets,
	plugin.CategoryIaC,
	plugin.CategoryDAST,
}

// categoryLabel gives each Category a human-readable heading, shared
// by the CLI summary, the HTML report, and (via dashboard.Summarize)
// the web UI, so all three describe categories identically.
var categoryLabel = map[plugin.Category]string{
	plugin.CategorySAST:    "Static Analysis (SAST)",
	plugin.CategorySCA:     "Dependencies (SCA)",
	plugin.CategorySecrets: "Secrets",
	plugin.CategoryIaC:     "Infrastructure (IaC)",
	plugin.CategoryDAST:    "Dynamic Analysis (DAST)",
}

// CategoryLabel returns category's display heading, or its raw value
// title-cased if it's not one of the five known categories (a future
// plugin adding a new category shouldn't render blank).
func CategoryLabel(c plugin.Category) string {
	if label, ok := categoryLabel[c]; ok {
		return label
	}
	if c == "" {
		return "Other"
	}
	return string(c)
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
	byCategory := make(map[plugin.Category]int)
	for _, f := range r.Findings {
		bySeverity[f.Severity]++
		byScanner[f.Scanner]++
		byCategory[f.Category]++
	}

	fmt.Fprintf(w, "\nScan of %s complete: %d findings\n\n", r.Target, len(r.Findings))

	fmt.Fprintln(w, "  By severity:")
	for _, sev := range summaryOrder {
		if n := bySeverity[sev]; n > 0 {
			fmt.Fprintf(w, "    %-8s %d\n", sev, n)
		}
	}

	fmt.Fprintln(w, "\n  By category:")
	for _, cat := range categoryOrder {
		if n := byCategory[cat]; n > 0 {
			fmt.Fprintf(w, "    %-24s %d\n", CategoryLabel(cat), n)
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
