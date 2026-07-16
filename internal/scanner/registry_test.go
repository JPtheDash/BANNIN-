package scanner_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jyotidash/bannin/internal/scanner"
	"github.com/jyotidash/bannin/pkg/plugin"
)

// fakeScanner is a minimal plugin.Scanner used to exercise the registry
// and manager without depending on any real, external tool.
type fakeScanner struct {
	name      string
	healthErr error
	runErr    error
	parseErr  error
	findings  []plugin.Finding
}

func (f *fakeScanner) Name() string    { return f.name }
func (f *fakeScanner) Version() string { return "test" }

func (f *fakeScanner) Run(ctx context.Context, target string) (plugin.RawResult, error) {
	if f.runErr != nil {
		return plugin.RawResult{}, f.runErr
	}
	return plugin.RawResult{Output: []byte(target)}, nil
}

func (f *fakeScanner) Parse(raw plugin.RawResult) ([]plugin.Finding, error) {
	if f.parseErr != nil {
		return nil, f.parseErr
	}
	return f.findings, nil
}

func (f *fakeScanner) HealthCheck(ctx context.Context) error {
	return f.healthErr
}

func TestRegistryRegisterAndLookup(t *testing.T) {
	r := scanner.NewRegistry()
	s := &fakeScanner{name: "fake"}
	r.Register(s)

	got, ok := r.Lookup("fake")
	if !ok {
		t.Fatal("Lookup(\"fake\") ok = false, want true")
	}
	if got != plugin.Scanner(s) {
		t.Error("Lookup returned a different Scanner than was registered")
	}

	if _, ok := r.Lookup("missing"); ok {
		t.Error("Lookup(\"missing\") ok = true, want false")
	}
}

func TestRegistryRegisterDuplicatePanics(t *testing.T) {
	r := scanner.NewRegistry()
	r.Register(&fakeScanner{name: "dup"})

	defer func() {
		if recover() == nil {
			t.Fatal("Register with a duplicate name should panic")
		}
	}()
	r.Register(&fakeScanner{name: "dup"})
}

func TestRegistryNamesSorted(t *testing.T) {
	r := scanner.NewRegistry()
	r.Register(&fakeScanner{name: "trivy"})
	r.Register(&fakeScanner{name: "gitleaks"})
	r.Register(&fakeScanner{name: "semgrep"})

	got := r.Names()
	want := []string{"gitleaks", "semgrep", "trivy"}
	if len(got) != len(want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Names() = %v, want %v", got, want)
		}
	}
}

var errFakeUnhealthy = errors.New("tool not installed")
