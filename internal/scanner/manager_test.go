package scanner_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jyotidash/bannin/internal/scanner"
	"github.com/jyotidash/bannin/pkg/plugin"
)

func newTestManager(scanners ...*fakeScanner) (*scanner.Manager, *scanner.Registry) {
	r := scanner.NewRegistry()
	for _, s := range scanners {
		r.Register(s)
	}
	return scanner.NewManager(r), r
}

func TestManagerResolveSuccess(t *testing.T) {
	mgr, _ := newTestManager(&fakeScanner{name: "semgrep"}, &fakeScanner{name: "osv"})

	scanners, err := mgr.Resolve([]string{"semgrep", "osv"})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(scanners) != 2 {
		t.Fatalf("Resolve returned %d scanners, want 2", len(scanners))
	}
}

func TestManagerResolveUnknownPlugin(t *testing.T) {
	mgr, _ := newTestManager(&fakeScanner{name: "semgrep"})

	_, err := mgr.Resolve([]string{"semgrep", "no-such-plugin"})
	if err == nil {
		t.Fatal("Resolve should error on an unregistered plugin name")
	}
}

func TestManagerScanCollectsFindings(t *testing.T) {
	finding := plugin.Finding{ID: "f1", Severity: plugin.SeverityHigh}
	mgr, _ := newTestManager(&fakeScanner{name: "semgrep", findings: []plugin.Finding{finding}})

	scanners, err := mgr.Resolve([]string{"semgrep"})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	results := mgr.Scan(context.Background(), ".", scanners)
	if len(results) != 1 {
		t.Fatalf("Scan returned %d results, want 1", len(results))
	}
	if results[0].Err != nil {
		t.Fatalf("Scan result Err = %v, want nil", results[0].Err)
	}
	if len(results[0].Findings) != 1 || results[0].Findings[0].ID != "f1" {
		t.Errorf("Scan result Findings = %v, want [%v]", results[0].Findings, finding)
	}
}

func TestManagerScanOnePluginFailingDoesNotStopOthers(t *testing.T) {
	healthy := &fakeScanner{name: "osv", findings: []plugin.Finding{{ID: "ok"}}}
	unhealthy := &fakeScanner{name: "semgrep", healthErr: errFakeUnhealthy}
	mgr, _ := newTestManager(unhealthy, healthy)

	scanners, err := mgr.Resolve([]string{"semgrep", "osv"})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	results := mgr.Scan(context.Background(), ".", scanners)
	if len(results) != 2 {
		t.Fatalf("Scan returned %d results, want 2", len(results))
	}

	var sawFailure, sawSuccess bool
	for _, r := range results {
		switch r.Plugin {
		case "semgrep":
			if r.Err == nil || !errors.Is(r.Err, errFakeUnhealthy) {
				t.Errorf("semgrep result Err = %v, want wrapping %v", r.Err, errFakeUnhealthy)
			}
			sawFailure = true
		case "osv":
			if r.Err != nil {
				t.Errorf("osv result Err = %v, want nil", r.Err)
			}
			sawSuccess = true
		}
	}
	if !sawFailure || !sawSuccess {
		t.Fatalf("expected one failing and one succeeding result, got %+v", results)
	}
}

func TestManagerScanEmptyRegistryUsesDefault(t *testing.T) {
	mgr := scanner.NewManager(nil)
	if _, err := mgr.Resolve([]string{"anything"}); err == nil {
		t.Fatal("Resolve against an empty DefaultRegistry should error")
	}
}

func TestCollectMergesOnlySuccessfulResults(t *testing.T) {
	results := []scanner.Result{
		{Plugin: "semgrep", Findings: []plugin.Finding{{ID: "s1"}, {ID: "s2"}}},
		{Plugin: "trivy", Err: errFakeUnhealthy, Findings: []plugin.Finding{{ID: "poisoned"}}},
		{Plugin: "osv", Findings: []plugin.Finding{{ID: "o1"}}},
		{Plugin: "gitleaks"},
	}

	got := scanner.Collect(results)
	if len(got) != 3 {
		t.Fatalf("Collect returned %d findings, want 3", len(got))
	}
	for _, f := range got {
		if f.ID == "poisoned" {
			t.Error("Collect included findings from a failed plugin")
		}
	}
}
