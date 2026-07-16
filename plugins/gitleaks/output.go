package gitleaks

// gitleaksFinding mirrors one entry of Gitleaks' JSON report — a
// top-level array, not an object — trimmed to the fields this plugin
// uses. Secret/Match are deliberately not modeled: Run always passes
// --redact, and even redacted placeholders have no place in a Finding.
type gitleaksFinding struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	Fingerprint string `json:"Fingerprint"`
}
