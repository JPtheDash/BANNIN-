package correlation

import (
	"path/filepath"
	"testing"

	"github.com/jyotidash/bannin/pkg/plugin"
)

func TestNormalizePaths(t *testing.T) {
	target := t.TempDir()
	outside := filepath.Join(filepath.Dir(target), "elsewhere", "file.go")

	findings := []plugin.Finding{
		{ID: "abs-under-target", Location: plugin.Location{Path: filepath.Join(target, "src", "main.py")}},
		{ID: "already-relative", Location: plugin.Location{Path: "requirements.txt"}},
		{ID: "dot-slash", Location: plugin.Location{Path: "./Dockerfile"}},
		{ID: "url", Location: plugin.Location{Path: "http://127.0.0.1:5000/login"}},
		{ID: "abs-outside-target", Location: plugin.Location{Path: outside}},
		{ID: "no-path", Location: plugin.Location{}},
	}

	NormalizePaths(findings, target)

	want := map[string]string{
		"abs-under-target":   filepath.Join("src", "main.py"),
		"already-relative":   "requirements.txt",
		"dot-slash":          "Dockerfile",
		"url":                "http://127.0.0.1:5000/login",
		"abs-outside-target": outside,
		"no-path":            "",
	}
	for _, f := range findings {
		if f.Location.Path != want[f.ID] {
			t.Errorf("%s: Path = %q, want %q", f.ID, f.Location.Path, want[f.ID])
		}
	}
}

// The scan target itself is usually given relative ("./examples/demo-app");
// absolute scanner output must still normalize against it.
func TestNormalizePathsRelativeTarget(t *testing.T) {
	abs, err := filepath.Abs("testdata-target")
	if err != nil {
		t.Fatal(err)
	}
	findings := []plugin.Finding{
		{Location: plugin.Location{Path: filepath.Join(abs, "go.mod")}},
	}

	NormalizePaths(findings, "testdata-target")

	if got := findings[0].Location.Path; got != "go.mod" {
		t.Errorf("Path = %q, want %q", got, "go.mod")
	}
}
