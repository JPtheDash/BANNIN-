package semgrep

import "encoding/json"

// semgrepOutput mirrors the shape of `semgrep --json` output (trimmed to
// the fields this plugin uses).
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
}

type semgrepExtra struct {
	Message  string          `json:"message"`
	Severity string          `json:"severity"`
	Metadata semgrepMetadata `json:"metadata"`
}

type semgrepMetadata struct {
	CWE        cweList  `json:"cwe"`
	References []string `json:"references"`
}

// cweList unmarshals Semgrep's "cwe" metadata field, which different
// rule sources populate as either a single string or an array of
// strings.
type cweList []string

func (c *cweList) UnmarshalJSON(data []byte) error {
	var multi []string
	if err := json.Unmarshal(data, &multi); err == nil {
		*c = multi
		return nil
	}

	var single string
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	if single == "" {
		*c = nil
		return nil
	}
	*c = []string{single}
	return nil
}
