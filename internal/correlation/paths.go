package correlation

import (
	"path/filepath"
	"strings"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// NormalizePaths rewrites each finding's Location.Path to be relative to
// the scan target, in place. Scanners disagree here — OSV Scanner
// reports absolute lockfile paths while Trivy reports target-relative
// ones — and that disagreement both leaks the local directory layout
// into reports and defeats correlation, which compares paths literally.
//
// URLs (ZAP targets) are left alone. Absolute paths that don't sit
// under the target are also left alone: making them relative would
// fabricate a "../…" location, and keeping them absolute is honest
// about the finding pointing outside the scanned tree.
func NormalizePaths(findings []plugin.Finding, target string) {
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return
	}
	for i := range findings {
		p := findings[i].Location.Path
		if p == "" || strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
			continue
		}
		if !filepath.IsAbs(p) {
			// Already relative; just canonicalize spellings like "./x".
			findings[i].Location.Path = filepath.Clean(p)
			continue
		}
		rel, err := filepath.Rel(absTarget, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		findings[i].Location.Path = rel
	}
}
