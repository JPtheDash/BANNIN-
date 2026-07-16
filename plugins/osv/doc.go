// Package osv wraps the OSV Scanner dependency vulnerability tool as a
// BANNIN plugin satisfying pkg/plugin.Scanner. Like plugins/semgrep, it
// depends only on pkg/plugin and the standard library — never on
// internal/. Registering Plugin against a scanner.Registry is
// cmd/bannin's job (the composition root), not this package's.
package osv
