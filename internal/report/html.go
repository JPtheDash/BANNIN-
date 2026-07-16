package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"

	"github.com/jyotidash/bannin/pkg/plugin"
)

//go:embed template.html
var htmlTemplate string

var reportTmpl = template.Must(template.New("report").Parse(htmlTemplate))

// htmlView is the template's view model: the Report plus the aggregates
// the page displays. Building them here keeps the template logic-free.
type htmlView struct {
	Report
	Total      int
	Tiles      []severityTile
	Scanners   []scannerCount
	Categories []categorySection
}

type severityTile struct {
	Severity plugin.Severity
	Count    int
}

type scannerCount struct {
	Name  string
	Count int
}

// categorySection groups a slice of the report's findings under one
// Category heading, in the same risk order they already carry from
// Report.Findings — so a categorized report doesn't sacrifice the
// "what to fix first" ordering, just organizes it.
type categorySection struct {
	Category plugin.Category
	Label    string
	Findings []Finding
}

// WriteHTML renders the report as a single self-contained HTML file
// (inline CSS, no JavaScript, no external assets) at dir/report.html,
// creating dir if needed, and returns the written file's path. All
// finding content is rendered through html/template's contextual
// escaping: scanner output — advisory descriptions, rule titles,
// reference URLs — is untrusted input to this page, and a malicious
// advisory must not become script in a security report.
func WriteHTML(dir string, r Report) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("report: creating %s: %w", dir, err)
	}

	view := htmlView{
		Report:     r,
		Total:      len(r.Findings),
		Tiles:      severityTiles(r.Findings),
		Categories: categorySections(r.Findings),
	}
	counts := make(map[string]int)
	for _, f := range r.Findings {
		counts[f.Scanner]++
	}
	// Preserve the configured plugin order rather than sorting names, so
	// the page mirrors what the user asked to run.
	for _, name := range r.Plugins {
		view.Scanners = append(view.Scanners, scannerCount{Name: name, Count: counts[name]})
	}

	path := filepath.Join(dir, "report.html")
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("report: writing %s: %w", path, err)
	}
	defer f.Close()

	if err := reportTmpl.Execute(f, view); err != nil {
		return "", fmt.Errorf("report: rendering HTML: %w", err)
	}
	return path, nil
}

// severityTiles returns one tile per severity, most severe first, zeros
// included so the tile row's layout is stable across reports.
func severityTiles(findings []Finding) []severityTile {
	counts := make(map[plugin.Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	tiles := make([]severityTile, 0, len(summaryOrder))
	for _, sev := range summaryOrder {
		tiles = append(tiles, severityTile{Severity: sev, Count: counts[sev]})
	}
	return tiles
}

// categorySections partitions findings into categoryOrder's buckets,
// skipping empty ones, preserving each bucket's existing risk order.
// Any finding whose Category isn't one of the five known values (there
// shouldn't be any — every built-in plugin sets one) falls into a
// trailing "Other" bucket rather than being silently dropped.
func categorySections(findings []Finding) []categorySection {
	byCategory := make(map[plugin.Category][]Finding)
	for _, f := range findings {
		byCategory[f.Category] = append(byCategory[f.Category], f)
	}

	order := append([]plugin.Category{}, categoryOrder...)
	known := make(map[plugin.Category]bool, len(categoryOrder))
	for _, c := range categoryOrder {
		known[c] = true
	}
	var unknown []plugin.Category
	for c := range byCategory {
		if !known[c] {
			unknown = append(unknown, c)
		}
	}
	sort.Slice(unknown, func(i, j int) bool { return unknown[i] < unknown[j] })
	order = append(order, unknown...)

	sections := make([]categorySection, 0, len(order))
	for _, c := range order {
		if fs := byCategory[c]; len(fs) > 0 {
			sections = append(sections, categorySection{Category: c, Label: CategoryLabel(c), Findings: fs})
		}
	}
	return sections
}
