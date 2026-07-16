package dashboard_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/jyotidash/bannin/internal/dashboard"
	"github.com/jyotidash/bannin/internal/report"
	"github.com/jyotidash/bannin/internal/storage"
	"github.com/jyotidash/bannin/pkg/plugin"
)

func openTestSQLStore(t *testing.T) *dashboard.SQLStore {
	t.Helper()
	s, err := storage.Open("sqlite", filepath.Join(t.TempDir(), "bannin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return dashboard.NewSQLStore(s)
}

func TestSQLStoreLatestEmpty(t *testing.T) {
	s := openTestSQLStore(t)
	if _, err := s.Latest(); !errors.Is(err, dashboard.ErrNoReport) {
		t.Errorf("Latest() on an empty store error = %v, want dashboard.ErrNoReport", err)
	}
}

func TestSQLStoreRoundTrip(t *testing.T) {
	s := openTestSQLStore(t)
	backing, err := storage.Open("sqlite", filepath.Join(t.TempDir(), "bannin2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer backing.Close()
	s2 := dashboard.NewSQLStore(backing)

	findings := []plugin.Finding{{ID: "1", Scanner: "trivy", RuleID: "CVE-1", Severity: plugin.SeverityCritical}}
	id, err := backing.Save(report.New("./demo", []string{"trivy"}, findings))
	if err != nil {
		t.Fatal(err)
	}

	got, err := s2.Get(id)
	if err != nil {
		t.Fatalf("Get(%d) returned error: %v", id, err)
	}
	if got.Target != "./demo" {
		t.Errorf("Get(%d).Target = %q, want %q", id, got.Target, "./demo")
	}

	entries, err := s.History(10) // s is a separate empty store — must not see s2's data.
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("unrelated store's History() = %v, want empty", entries)
	}

	entries2, err := s2.History(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries2) != 1 || entries2[0].ID != id {
		t.Errorf("History() = %+v, want the one saved report", entries2)
	}
}

func TestSQLStoreGetUnknownIDTranslatesError(t *testing.T) {
	s := openTestSQLStore(t)
	if _, err := s.Get(999); !errors.Is(err, dashboard.ErrNoReport) {
		t.Errorf("Get(999) error = %v, want dashboard.ErrNoReport (translated from storage.ErrNotFound)", err)
	}
}
