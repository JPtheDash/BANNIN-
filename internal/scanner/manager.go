package scanner

import (
	"context"
	"fmt"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// Result is the outcome of running one Scanner plugin: either Findings or
// Err explaining why the plugin didn't complete. One plugin failing
// doesn't stop the others from running.
type Result struct {
	Plugin   string
	Findings []plugin.Finding
	Err      error
}

// Manager resolves configured plugin names against a Registry and drives
// them against a target. Parallel execution is internal/scheduler's job
// (a later milestone); Manager runs plugins sequentially.
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

// Scan runs each of the given scanners against target in sequence,
// collecting one Result per plugin regardless of whether earlier plugins
// failed.
func (m *Manager) Scan(ctx context.Context, target string, scanners []plugin.Scanner) []Result {
	results := make([]Result, 0, len(scanners))
	for _, s := range scanners {
		results = append(results, runOne(ctx, target, s))
	}
	return results
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

func runOne(ctx context.Context, target string, s plugin.Scanner) Result {
	name := s.Name()

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
