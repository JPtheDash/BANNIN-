// Package gitleaks wraps Gitleaks secret scanning as a BANNIN plugin
// satisfying pkg/plugin.Scanner. Like the other plugins, it depends only
// on pkg/plugin and the standard library — never on internal/.
// Registering Plugin against a scanner.Registry is cmd/bannin's job (the
// composition root), not this package's.
//
// Scans always run with --redact: a leaked secret's value must never be
// carried through BANNIN's findings, reports, or storage — the finding
// points at the file/line, which is all remediation needs.
package gitleaks
