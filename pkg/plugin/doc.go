// Package plugin holds the public plugin SDK: the Scanner interface and
// the shared Finding model that every scanner plugin normalizes its
// output into.
//
// It lives under pkg/ rather than internal/ because plugins are ports in
// the hexagonal architecture: the orchestrator depends on this contract,
// never on a concrete scanner, and third-party plugin authors need to be
// able to import it from outside this module.
//
// Deferred: concrete Scanner implementations (plugins/semgrep,
// plugins/osv, ...) and the internal/scanner manager that discovers and
// drives them are later milestones. This package only defines the
// contract they build on.
package plugin
