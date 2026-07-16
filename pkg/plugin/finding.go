package plugin

// Severity is the normalized severity level of a Finding. Plugins must
// map their tool's native severity/confidence scale onto these values.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Location pinpoints where a Finding was detected in the scanned target.
// JSON tags define the stable serialization used by report.json and
// every future exporter; changing them is a breaking schema change.
type Location struct {
	// Path is the file path the finding applies to, relative to the scan
	// target. Empty for findings with no single file (e.g. some
	// dependency or container findings).
	Path      string `json:"path,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

// Finding is the normalized model every scanner plugin's Parse method
// produces. internal/correlation, internal/risk, internal/policy, and
// internal/report all operate on Findings, never on a plugin's raw
// output.
type Finding struct {
	// ID uniquely identifies this finding within a single scan run.
	// Cross-run/cross-scanner deduplication is internal/correlation's
	// job, not the plugin's.
	ID string `json:"id"`
	// Scanner is the producing plugin's Name(), so a Finding remains
	// traceable to its source after Findings from multiple scanners are
	// merged.
	Scanner string `json:"scanner"`
	// RuleID is the underlying tool's rule/check identifier (e.g. a
	// Semgrep rule ID or a CVE for a dependency finding).
	RuleID string `json:"rule_id"`
	// Aliases lists alternate identifiers for the same underlying issue
	// under other schemes (e.g. a GHSA advisory's CVE and PYSEC ids).
	// internal/correlation uses these to recognize one advisory reported
	// by multiple scanners; plugins populate them when the tool provides
	// them.
	Aliases     []string `json:"aliases,omitempty"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Severity    Severity `json:"severity"`
	Location    Location `json:"location"`
	// CWE lists applicable CWE identifiers (e.g. "CWE-89"), if any.
	CWE []string `json:"cwe,omitempty"`
	// References are URLs for further reading (advisories, rule docs).
	References []string `json:"references,omitempty"`
	// Metadata carries plugin-specific extras that don't fit the common
	// fields above, keyed by the plugin.
	Metadata map[string]string `json:"metadata,omitempty"`
}
