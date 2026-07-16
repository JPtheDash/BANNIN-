package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// Report is the envelope around a scan's normalized findings — the one
// artifact every output format (JSON today; HTML, SARIF, dashboard,
// policy evaluation later) is rendered from. Findings are expected to
// arrive already normalized, deduplicated, and sorted by the pipeline.
type Report struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Target      string           `json:"target"`
	Plugins     []string         `json:"plugins"`
	Findings    []plugin.Finding `json:"findings"`
}

// New assembles a Report for the given scan. findings may be nil; it is
// stored as an empty (never null) slice so consumers of the JSON can
// always range over .findings.
func New(target string, plugins []string, findings []plugin.Finding) Report {
	if findings == nil {
		findings = []plugin.Finding{}
	}
	return Report{
		GeneratedAt: time.Now().UTC(),
		Target:      target,
		Plugins:     plugins,
		Findings:    findings,
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
