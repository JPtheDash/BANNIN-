package trivy

// trivyOutput mirrors the shape of `trivy fs --format json` output
// (trimmed to the fields this plugin uses).
type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string                  `json:"Target"`
	Vulnerabilities   []trivyVulnerability    `json:"Vulnerabilities"`
	Misconfigurations []trivyMisconfiguration `json:"Misconfigurations"`
}

type trivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	CweIDs           []string `json:"CweIDs"`
	References       []string `json:"References"`
}

type trivyMisconfiguration struct {
	ID            string             `json:"ID"`
	Title         string             `json:"Title"`
	Description   string             `json:"Description"`
	Message       string             `json:"Message"`
	Severity      string             `json:"Severity"`
	References    []string           `json:"References"`
	CauseMetadata trivyCauseMetadata `json:"CauseMetadata"`
}

type trivyCauseMetadata struct {
	StartLine int `json:"StartLine"`
	EndLine   int `json:"EndLine"`
}
