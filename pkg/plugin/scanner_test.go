package plugin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// fakeScanner is a minimal Scanner implementation used to prove the
// interface is actually implementable and usable by callers, the way a
// real plugin (plugins/semgrep, plugins/osv, ...) will be.
type fakeScanner struct {
	healthy bool
}

func (f *fakeScanner) Name() string    { return "fake" }
func (f *fakeScanner) Version() string { return "1.2.3" }

func (f *fakeScanner) Run(ctx context.Context, target string) (plugin.RawResult, error) {
	return plugin.RawResult{Output: []byte(`{"target":"` + target + `"}`), ExitCode: 0}, nil
}

func (f *fakeScanner) Parse(raw plugin.RawResult) ([]plugin.Finding, error) {
	return []plugin.Finding{
		{
			ID:       "fake-1",
			Scanner:  f.Name(),
			RuleID:   "fake-rule",
			Title:    "example finding",
			Severity: plugin.SeverityHigh,
			Location: plugin.Location{Path: "main.go", StartLine: 10, EndLine: 12},
		},
	}, nil
}

func (f *fakeScanner) HealthCheck(ctx context.Context) error {
	if !f.healthy {
		return errors.New("fake tool not installed")
	}
	return nil
}

var _ plugin.Scanner = (*fakeScanner)(nil)

func TestScannerLifecycle(t *testing.T) {
	s := &fakeScanner{healthy: true}
	ctx := context.Background()

	if err := s.HealthCheck(ctx); err != nil {
		t.Fatalf("HealthCheck returned error: %v", err)
	}

	raw, err := s.Run(ctx, "./testdata")
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if got := findings[0].Scanner; got != s.Name() {
		t.Errorf("Finding.Scanner = %q, want %q", got, s.Name())
	}
	if got := findings[0].Severity; got != plugin.SeverityHigh {
		t.Errorf("Finding.Severity = %q, want %q", got, plugin.SeverityHigh)
	}
}

func TestScannerHealthCheckFailure(t *testing.T) {
	s := &fakeScanner{healthy: false}
	if err := s.HealthCheck(context.Background()); err == nil {
		t.Fatal("HealthCheck should return an error when the tool is unhealthy")
	}
}

func TestSeverityValuesAreDistinct(t *testing.T) {
	seen := map[plugin.Severity]bool{}
	for _, sev := range []plugin.Severity{
		plugin.SeverityCritical,
		plugin.SeverityHigh,
		plugin.SeverityMedium,
		plugin.SeverityLow,
		plugin.SeverityInfo,
	} {
		if seen[sev] {
			t.Errorf("duplicate severity value: %q", sev)
		}
		seen[sev] = true
	}
}
