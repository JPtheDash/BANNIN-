package checkov

import (
	"encoding/json"
	"fmt"
)

// Checkov's -o json output takes three shapes depending on what it
// scanned: a single report object when one framework matched (e.g. only
// Dockerfiles), a JSON array of report objects when several matched
// (terraform + dockerfile + ...), and a bare run-summary object with no
// check_type/results keys at all when nothing was scannable.
// decodeReports normalizes all three into a slice.
func decodeReports(data []byte) ([]checkovReport, error) {
	trimmed := firstNonSpace(data)

	if trimmed == '[' {
		var reports []checkovReport
		if err := json.Unmarshal(data, &reports); err != nil {
			return nil, err
		}
		return reports, nil
	}

	var single checkovReport
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, err
	}
	if single.CheckType == "" {
		// The bare summary shape: a valid run that scanned nothing.
		return nil, nil
	}
	return []checkovReport{single}, nil
}

func firstNonSpace(data []byte) byte {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		}
		return b
	}
	return 0
}

type checkovReport struct {
	CheckType string         `json:"check_type"`
	Results   checkovResults `json:"results"`
}

type checkovResults struct {
	FailedChecks []checkovCheck `json:"failed_checks"`
}

type checkovCheck struct {
	CheckID       string `json:"check_id"`
	CheckName     string `json:"check_name"`
	FilePath      string `json:"file_path"`
	FileLineRange []int  `json:"file_line_range"`
	Severity      string `json:"severity"`
	Guideline     string `json:"guideline"`
	Resource      string `json:"resource"`
}

func (c checkovCheck) lines() (start, end int) {
	if len(c.FileLineRange) > 0 {
		start = c.FileLineRange[0]
	}
	if len(c.FileLineRange) > 1 {
		end = c.FileLineRange[1]
	}
	return start, end
}

// UnmarshalJSON tolerates severity being JSON null (the common case in
// the open-source build, where severities are an enterprise feature).
func (c *checkovCheck) UnmarshalJSON(data []byte) error {
	type alias checkovCheck
	var a struct {
		alias
		Severity *string `json:"severity"`
	}
	if err := json.Unmarshal(data, &a); err != nil {
		return fmt.Errorf("checkov check: %w", err)
	}
	*c = checkovCheck(a.alias)
	if a.Severity != nil {
		c.Severity = *a.Severity
	}
	return nil
}
