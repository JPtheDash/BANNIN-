// Package semgrep wraps the Semgrep static analysis tool as a BANNIN
// plugin satisfying pkg/plugin.Scanner. It depends only on pkg/plugin and
// the standard library — never on internal/ — per the architecture rule
// that plugins are driven adapters, not orchestrator internals.
// Registering Plugin against a scanner.Registry is cmd/bannin's job (the
// composition root), not this package's.
package semgrep
