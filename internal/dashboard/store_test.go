package dashboard_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jyotidash/bannin/internal/dashboard"
	"github.com/jyotidash/bannin/internal/report"
	"github.com/jyotidash/bannin/pkg/plugin"
)

func TestFileStoreLatestNoReportYet(t *testing.T) {
	s := dashboard.NewFileStore(t.TempDir())

	_, err := s.Latest()
	if !errors.Is(err, dashboard.ErrNoReport) {
		t.Errorf("Latest() error = %v, want ErrNoReport", err)
	}
}

func TestFileStoreLatestReadsWrittenReport(t *testing.T) {
	dir := t.TempDir()
	findings := []plugin.Finding{
		{ID: "1", Scanner: "semgrep", RuleID: "eval", Title: "eval() use", Severity: plugin.SeverityHigh,
			Location: plugin.Location{Path: "app.py", StartLine: 4}},
	}
	if _, err := report.WriteJSON(dir, report.New("./demo", []string{"semgrep"}, findings)); err != nil {
		t.Fatal(err)
	}

	s := dashboard.NewFileStore(dir)
	got, err := s.Latest()
	if err != nil {
		t.Fatalf("Latest() returned error: %v", err)
	}
	if got.Target != "./demo" || len(got.Findings) != 1 {
		t.Fatalf("Latest() = %+v, want the written report", got)
	}
	if got.Findings[0].Risk.Score == 0 {
		t.Error("Latest() lost the risk assessment on round-trip")
	}
}

func TestFileStoreLatestCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "report.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := dashboard.NewFileStore(dir)
	if _, err := s.Latest(); err == nil {
		t.Fatal("Latest() should error on a corrupt report file")
	} else if errors.Is(err, dashboard.ErrNoReport) {
		t.Error("Latest() should distinguish a corrupt file from a missing one")
	}
}

func TestFileStoreHistoryEmptyWhenNoReport(t *testing.T) {
	s := dashboard.NewFileStore(t.TempDir())

	entries, err := s.History(10)
	if err != nil {
		t.Fatalf("History() returned error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("History() = %v, want empty (no scan yet is not an error)", entries)
	}
}

func TestFileStoreHistoryAndGetSyntheticID(t *testing.T) {
	dir := t.TempDir()
	findings := []plugin.Finding{{ID: "1", Scanner: "gitleaks", RuleID: "aws-key", Severity: plugin.SeverityHigh}}
	if _, err := report.WriteJSON(dir, report.New("./demo", []string{"gitleaks"}, findings)); err != nil {
		t.Fatal(err)
	}
	s := dashboard.NewFileStore(dir)

	entries, err := s.History(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != 0 || entries[0].Total != 1 {
		t.Fatalf("History() = %+v, want one synthetic entry (id 0) for the file's report", entries)
	}

	got, err := s.Get(0)
	if err != nil {
		t.Fatalf("Get(0) returned error: %v", err)
	}
	if got.Target != "./demo" {
		t.Errorf("Get(0).Target = %q, want %q", got.Target, "./demo")
	}

	if _, err := s.Get(1); !errors.Is(err, dashboard.ErrNoReport) {
		t.Errorf("Get(1) error = %v, want ErrNoReport (FileStore only knows id 0)", err)
	}
}
