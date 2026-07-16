package plugin

import "context"

// Scanner is the port every BANNIN scanner plugin implements. The
// orchestrator (internal/scanner) depends only on this interface, never
// on a concrete plugin package — plugins are registered and loaded
// dynamically against this contract.
type Scanner interface {
	// Name returns the plugin's short, stable identifier (e.g. "semgrep"),
	// used in configuration, logs, and reports.
	Name() string

	// Version returns the version of the underlying scanning tool, or
	// "unknown" if it cannot be determined.
	Version() string

	// Run executes the underlying tool against target and returns its
	// unprocessed output. Run does not normalize output into Findings;
	// that's Parse's job, so a scan's execution and its interpretation
	// can be tested and retried independently.
	Run(ctx context.Context, target string) (RawResult, error)

	// Parse converts a RawResult produced by Run into normalized Findings.
	Parse(raw RawResult) ([]Finding, error)

	// HealthCheck reports whether the underlying tool is installed and
	// usable (e.g. present on PATH, license valid) without running a scan.
	HealthCheck(ctx context.Context) error
}

// RawResult is the unprocessed output of a single Scanner.Run call,
// passed on to Parse.
type RawResult struct {
	// Output is the tool's primary result payload (commonly JSON on
	// stdout).
	Output []byte
	// Stderr captures diagnostic output the tool wrote separately from
	// Output, for logging when a scan fails or behaves unexpectedly.
	Stderr []byte
	// ExitCode is the underlying process's exit status. Many scanners
	// (e.g. Semgrep, Trivy) use a nonzero code to mean "findings
	// reported", not "tool failed" — Parse, not Run, is responsible for
	// interpreting it.
	ExitCode int
}
