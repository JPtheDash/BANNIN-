package osv

// osvOutput mirrors the shape of `osv-scanner scan source --format json`
// output (trimmed to the fields this plugin uses).
type osvOutput struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
}

type osvPackage struct {
	Package         osvPackageInfo     `json:"package"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
}

type osvPackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVulnerability struct {
	ID               string              `json:"id"`
	Aliases          []string            `json:"aliases"`
	Summary          string              `json:"summary"`
	Details          string              `json:"details"`
	References       []osvReference      `json:"references"`
	Severity         []osvSeverityEntry  `json:"severity"`
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
}

type osvReference struct {
	URL string `json:"url"`
}

// osvSeverityEntry is a CVSS-style entry (e.g. {"type":"CVSS_V3","score":"9.8"}),
// present on some ecosystems' advisories and absent on others.
type osvSeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvDatabaseSpecific struct {
	Severity string `json:"severity"`
}
