// Package trivy wraps Trivy's filesystem scan (dependency vulnerabilities
// + IaC misconfigurations) as a BANNIN plugin satisfying
// pkg/plugin.Scanner. Like plugins/semgrep and plugins/osv, it depends
// only on pkg/plugin and the standard library — never on internal/.
// Registering Plugin against a scanner.Registry is cmd/bannin's job (the
// composition root), not this package's.
package trivy
