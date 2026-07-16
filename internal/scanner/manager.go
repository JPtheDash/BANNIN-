package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/jyotidash/bannin/internal/scheduler"
	"github.com/jyotidash/bannin/pkg/plugin"
)

// Result is the outcome of running one Scanner plugin: either Findings or
// Err explaining why the plugin didn't complete. One plugin failing
// doesn't stop the others from running.
type Result struct {
	Plugin   string
	Findings []plugin.Finding
	Err      error
	// Duration covers the plugin's health check, Run, and Parse — the
	// full time this plugin held up the scan. Reported per-plugin
	// (rather than only the scan's total wall time) so a dashboard can
	// show which scanner is slow, not just that the scan was slow.
	Duration time.Duration
}

// Manager resolves configured plugin names against a Registry and drives
// them against a target. Concurrency policy lives in internal/scheduler;
// Manager only defines what running one plugin means.
type Manager struct {
	registry *Registry
}

// NewManager returns a Manager backed by registry. A nil registry falls
// back to DefaultRegistry.
func NewManager(registry *Registry) *Manager {
	if registry == nil {
		registry = DefaultRegistry
	}
	return &Manager{registry: registry}
}

// Resolve looks up each requested plugin name in the registry, returning
// an error listing every name that isn't registered. Callers should call
// Resolve before Scan so a misconfigured plugin name (e.g. a typo) is
// caught before any tool runs.
func (m *Manager) Resolve(names []string) ([]plugin.Scanner, error) {
	scanners := make([]plugin.Scanner, 0, len(names))
	var missing []string

	for _, name := range names {
		s, ok := m.registry.Lookup(name)
		if !ok {
			missing = append(missing, name)
			continue
		}
		scanners = append(scanners, s)
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("scanner: unknown plugin(s) %v (registered: %v)", missing, m.registry.Names())
	}
	return scanners, nil
}

// Scan runs the given scanners against target concurrently (they spend
// their time waiting on external tool subprocesses, so they all run at
// once), collecting one Result per plugin regardless of failures.
// Results arrive in the same order as scanners, so output stays
// deterministic even though completion order isn't.
func (m *Manager) Scan(ctx context.Context, target string, scanners []plugin.Scanner) []Result {
	return scheduler.Map(ctx, 0, scanners, func(ctx context.Context, s plugin.Scanner) Result {
		return runOne(ctx, target, s)
	})
}

// Collect merges every successful Result's findings into one slice — the
// normalized collection the rest of the pipeline (correlation, report,
// and later policy/dashboard) operates on. Failed plugins contribute
// nothing here; their errors stay on the individual Results for the
// caller to surface.
func Collect(results []Result) []plugin.Finding {
	var findings []plugin.Finding
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		findings = append(findings, r.Findings...)
	}
	return findings
}

func runOne(ctx context.Context, target string, s plugin.Scanner) (res Result) {
	name := s.Name()
	start := time.Now()

	// A plugin is third-party code driving an external tool; if it
	// panics it must fail as its own Result, not take down the whole
	// scan — especially now that plugins run on concurrent goroutines,
	// where an unrecovered panic kills the process.
	defer func() {
		if r := recover(); r != nil {
			res = Result{Plugin: name, Err: fmt.Errorf("plugin panicked: %v", r)}
		}
		res.Duration = time.Since(start)
	}()

	if err := s.HealthCheck(ctx); err != nil {
		return Result{Plugin: name, Err: fmt.Errorf("health check: %w", err)}
	}

	raw, err := s.Run(ctx, target)
	if err != nil {
		return Result{Plugin: name, Err: fmt.Errorf("run: %w", err)}
	}

	findings, err := s.Parse(raw)
	if err != nil {
		return Result{Plugin: name, Err: fmt.Errorf("parse: %w", err)}
	}

	return Result{Plugin: name, Findings: findings}
}
