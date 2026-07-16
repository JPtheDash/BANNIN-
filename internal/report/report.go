package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jyotidash/bannin/internal/risk"
	"github.com/jyotidash/bannin/pkg/plugin"
)

// Finding is a normalized finding enriched with its risk assessment.
// The embedded plugin.Finding serializes inline, so each findings[]
// entry in report.json keeps its existing keys and gains a "risk"
// object — an additive schema change.
type Finding struct {
	plugin.Finding
	Risk risk.Assessment `json:"risk"`
}

// Report is the envelope around a scan's normalized findings — the one
// artifact every output format (JSON today; HTML, SARIF, dashboard,
// policy evaluation later) is rendered from. Findings are expected to
// arrive already normalized, deduplicated, and sorted by the pipeline.
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Target      string    `json:"target"`
	Plugins     []string  `json:"plugins"`
	Findings    []Finding `json:"findings"`
}

// New assembles a Report for the given scan: each finding gets its risk
// assessment, and findings are ordered highest score first — the report
// is a prioritized work list, not a raw dump. The sort is stable, so
// the pipeline's deterministic severity sort breaks score ties.
// findings may be nil; the report stores an empty (never null) slice so
// consumers of the JSON can always range over .findings.
func New(target string, plugins []string, findings []plugin.Finding) Report {
	wrapped := make([]Finding, len(findings))
	for i, f := range findings {
		wrapped[i] = Finding{Finding: f, Risk: risk.Assess(f)}
	}
	sort.SliceStable(wrapped, func(i, j int) bool {
		return wrapped[i].Risk.Score > wrapped[j].Risk.Score
	})
	return Report{
		GeneratedAt: time.Now().UTC(),
		Target:      target,
		Plugins:     plugins,
		Findings:    wrapped,
	}
}

// WriteJSON writes the report as indented JSON to dir/report.json,
// creating dir if needed, and returns the written file's path.
func WriteJSON(dir string, r Report) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("report: creating %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("report: encoding: %w", err)
	}
	data = append(data, '\n')

	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("report: writing %s: %w", path, err)
	}
	return path, nil
}
