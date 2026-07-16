// Package checkov wraps Checkov IaC scanning (Terraform, Dockerfile,
// Kubernetes, ...) as a BANNIN plugin satisfying pkg/plugin.Scanner.
// Like the other plugins, it depends only on pkg/plugin and the
// standard library — never on internal/. Registering Plugin against a
// scanner.Registry is cmd/bannin's job (the composition root), not this
// package's.
package checkov
