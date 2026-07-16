package report_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jyotidash/bannin/internal/report"
	"github.com/jyotidash/bannin/pkg/plugin"
)

func TestWriteHTMLRendersFindings(t *testing.T) {
	dir := t.TempDir()
	r := report.New("./examples/demo-app", []string{"semgrep", "osv", "gitleaks"}, sampleFindings())

	path, err := report.WriteHTML(dir, r)
	if err != nil {
		t.Fatalf("WriteHTML returned error: %v", err)
	}
	if filepath.Base(path) != "report.html" {
		t.Errorf("wrote %q, want a report.html", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)

	for _, want := range []string{
		"./examples/demo-app", // target in header
		"3 findings",          // total
		"eval",                // finding title
		"github-pat",          // rule id
		"app.py",              // location
		"sev-high",            // severity styling hook
		"semgrep",             // scanner breakdown
		"<!doctype html>",     // complete document
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report.html missing %q", want)
		}
	}
	if strings.Contains(html, "<script") || strings.Contains(html, "src=") {
		t.Error("report.html should be self-contained with no scripts or external assets")
	}
}

func TestWriteHTMLEscapesUntrustedScannerOutput(t *testing.T) {
	// Advisory text and rule metadata come from scanned artifacts and
	// vulnerability databases — hostile input. A crafted advisory must
	// not become markup in the rendered report.
	hostile := []plugin.Finding{{
		ID:          "x",
		Scanner:     "semgrep",
		RuleID:      `"><script>alert(1)</script>`,
		Title:       `<img src=x onerror=alert(1)>`,
		Description: `<script>document.location='https://evil.example'</script>`,
		Severity:    plugin.SeverityHigh,
		References:  []string{`javascript:alert(1)`},
	}}

	dir := t.TempDir()
	path, err := report.WriteHTML(dir, report.New(".", []string{"semgrep"}, hostile))
	if err != nil {
		t.Fatalf("WriteHTML returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)

	if strings.Contains(html, "<script>") || strings.Contains(html, "<img src=x") {
		t.Error("hostile finding content rendered as live markup")
	}
	if strings.Contains(html, `href="javascript:`) {
		t.Error("javascript: URL survived into a live href")
	}
}

func TestWriteHTMLEmptyFindings(t *testing.T) {
	dir := t.TempDir()
	path, err := report.WriteHTML(dir, report.New(".", nil, nil))
	if err != nil {
		t.Fatalf("WriteHTML returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "No findings") {
		t.Error("empty report should state that there are no findings")
	}
}
