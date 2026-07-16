package storage_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jyotidash/bannin/internal/report"
	"github.com/jyotidash/bannin/internal/storage"
	"github.com/jyotidash/bannin/pkg/plugin"
)

func openTestStore(t *testing.T) *storage.Store {
	t.Helper()
	s, err := storage.Open("sqlite", filepath.Join(t.TempDir(), "bannin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenRejectsUnimplementedDriver(t *testing.T) {
	if _, err := storage.Open("postgres", "whatever"); err == nil {
		t.Fatal("Open should reject an unimplemented driver")
	}
}

func TestSaveGetRoundTrips(t *testing.T) {
	s := openTestStore(t)
	findings := []plugin.Finding{
		{ID: "1", Scanner: "semgrep", RuleID: "eval", Title: "eval", Severity: plugin.SeverityHigh,
			Location: plugin.Location{Path: "app.py", StartLine: 4}},
	}
	r := report.New("./demo", []string{"semgrep"}, findings)

	id, err := s.Save(r)
	if err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	got, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if got.Target != "./demo" || len(got.Findings) != 1 {
		t.Fatalf("Get(%d) = %+v, want the saved report", id, got)
	}
	if got.Findings[0].RuleID != "eval" || got.Findings[0].Risk.Score == 0 {
		t.Errorf("finding fields (including risk) lost in round-trip: %+v", got.Findings[0])
	}
}

func TestGetUnknownID(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Get(999); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get(999) error = %v, want ErrNotFound", err)
	}
}

func TestLatestEmptyStore(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Latest(); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Latest() on an empty store error = %v, want ErrNotFound", err)
	}
}

func TestLatestReturnsMostRecent(t *testing.T) {
	s := openTestStore(t)
	first := report.New("./a", nil, nil)
	second := report.New("./b", nil, nil)
	second.GeneratedAt = first.GeneratedAt.Add(time.Hour)

	if _, err := s.Save(first); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(second); err != nil {
		t.Fatal(err)
	}

	got, err := s.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if got.Target != "./b" {
		t.Errorf("Latest().Target = %q, want %q (the more recent scan)", got.Target, "./b")
	}
}

func TestListOrdersNewestFirstAndRespectsLimit(t *testing.T) {
	s := openTestStore(t)
	base := report.New("./a", nil, nil).GeneratedAt

	for i, target := range []string{"./a", "./b", "./c"} {
		r := report.New(target, nil, []plugin.Finding{{ID: "x", Severity: plugin.SeverityHigh}})
		r.GeneratedAt = base.Add(time.Duration(i) * time.Hour)
		if _, err := s.Save(r); err != nil {
			t.Fatal(err)
		}
	}

	all, err := s.List(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("List(0) returned %d entries, want 3", len(all))
	}
	if all[0].Target != "./c" || all[2].Target != "./a" {
		t.Errorf("List order = %v, want newest first (./c, ./b, ./a)", []string{all[0].Target, all[1].Target, all[2].Target})
	}
	if all[0].Total != 1 || all[0].BySeverity[plugin.SeverityHigh] != 1 {
		t.Errorf("List Meta = %+v, want total 1 and one high severity", all[0])
	}

	limited, err := s.List(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 2 {
		t.Errorf("List(2) returned %d entries, want 2", len(limited))
	}
}
