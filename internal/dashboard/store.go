// Package dashboard serves scan report data to the HTTP API
// (api/server, Milestone 18) and the web UI (Milestone 19).
//
// Store is the port: api/server depends only on it, never on how
// reports are actually persisted. Two implementations exist. FileStore
// reads the single report.json a scan just wrote — no history, because
// a file holds only what was last written to it; it is the fallback
// when storage.driver isn't "sqlite". SQLStore (Milestone 15) wraps
// internal/storage and gives real history: every scan since SQLite
// persistence was enabled, listable and individually fetchable.
// api/server and web/ don't know or care which one is behind the
// interface.
package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jyotidash/bannin/internal/report"
	"github.com/jyotidash/bannin/internal/storage"
	"github.com/jyotidash/bannin/pkg/plugin"
)

// ErrNoReport indicates no scan report is available at all (nothing
// has been scanned yet) or the specific one requested doesn't exist.
var ErrNoReport = errors.New("dashboard: no report available; run \"bannin scan\" first")

// HistoryEntry is one scan's listing metadata — cheap to fetch in
// bulk because it never carries the findings themselves.
type HistoryEntry struct {
	ID          int64                   `json:"id"`
	GeneratedAt time.Time               `json:"generated_at"`
	Target      string                  `json:"target"`
	Total       int                     `json:"total"`
	BySeverity  map[plugin.Severity]int `json:"by_severity"`
}

// Store gives the HTTP API access to scan report data without
// depending on how that data is stored.
type Store interface {
	// Latest returns the most recent scan report, or ErrNoReport if
	// none has been produced yet.
	Latest() (report.Report, error)
	// History returns up to limit past scans' metadata, most recent
	// first. A non-positive limit returns all of them. An empty result
	// is not an error — it means no scans have been recorded.
	History(limit int) ([]HistoryEntry, error)
	// Get returns the full report for a specific scan id (as listed by
	// History), or ErrNoReport if no such scan exists.
	Get(id int64) (report.Report, error)
	// Save persists r as a new scan and returns an id valid for Get.
	// Used by the on-demand scan endpoint (api/server) to record a
	// dashboard-triggered scan the same way `bannin scan` does.
	Save(r report.Report) (int64, error)
}

// FileStore is a Store backed by a single report.json file — the
// report.output_dir a scan just wrote to. It holds only the last
// scan's report, so its History is at most one synthetic entry (id 0)
// and Get only recognizes that id.
type FileStore struct {
	path string
}

// NewFileStore returns a FileStore that reads dir/report.json.
func NewFileStore(dir string) *FileStore {
	return &FileStore{path: filepath.Join(dir, "report.json")}
}

func (s *FileStore) Latest() (report.Report, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return report.Report{}, ErrNoReport
		}
		return report.Report{}, fmt.Errorf("dashboard: reading %s: %w", s.path, err)
	}

	var r report.Report
	if err := json.Unmarshal(data, &r); err != nil {
		return report.Report{}, fmt.Errorf("dashboard: parsing %s: %w", s.path, err)
	}
	return r, nil
}

func (s *FileStore) History(limit int) ([]HistoryEntry, error) {
	r, err := s.Latest()
	if errors.Is(err, ErrNoReport) {
		return []HistoryEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	bySeverity := make(map[plugin.Severity]int)
	for _, f := range r.Findings {
		bySeverity[f.Severity]++
	}
	return []HistoryEntry{{ID: 0, GeneratedAt: r.GeneratedAt, Target: r.Target, Total: len(r.Findings), BySeverity: bySeverity}}, nil
}

func (s *FileStore) Get(id int64) (report.Report, error) {
	if id != 0 {
		return report.Report{}, ErrNoReport
	}
	return s.Latest()
}

// Save overwrites report.json with r, mirroring what a `bannin scan` run
// would have written. FileStore only ever holds one report, so the
// scan just triggered becomes Latest/History's sole (id 0) entry.
func (s *FileStore) Save(r report.Report) (int64, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("dashboard: encoding report: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return 0, fmt.Errorf("dashboard: creating %s: %w", filepath.Dir(s.path), err)
	}
	if err := os.WriteFile(s.path, data, 0o644); err != nil {
		return 0, fmt.Errorf("dashboard: writing %s: %w", s.path, err)
	}
	return 0, nil
}

var _ Store = (*FileStore)(nil)

// SQLStore is a Store backed by internal/storage's SQLite persistence
// — real scan history, one row per `bannin scan` run.
type SQLStore struct {
	backing *storage.Store
}

// NewSQLStore wraps an open storage.Store as a dashboard Store.
func NewSQLStore(s *storage.Store) *SQLStore {
	return &SQLStore{backing: s}
}

func (s *SQLStore) Latest() (report.Report, error) {
	r, err := s.backing.Latest()
	return r, translateErr(err)
}

func (s *SQLStore) Get(id int64) (report.Report, error) {
	r, err := s.backing.Get(id)
	return r, translateErr(err)
}

func (s *SQLStore) Save(r report.Report) (int64, error) {
	return s.backing.Save(r)
}

func (s *SQLStore) History(limit int) ([]HistoryEntry, error) {
	metas, err := s.backing.List(limit)
	if err != nil {
		return nil, translateErr(err)
	}
	entries := make([]HistoryEntry, len(metas))
	for i, m := range metas {
		entries[i] = HistoryEntry{ID: m.ID, GeneratedAt: m.GeneratedAt, Target: m.Target, Total: m.Total, BySeverity: m.BySeverity}
	}
	return entries, nil
}

// translateErr maps storage's not-found sentinel onto dashboard's, so
// api/server only ever needs to check for one error across both Store
// implementations.
func translateErr(err error) error {
	if errors.Is(err, storage.ErrNotFound) {
		return ErrNoReport
	}
	return err
}

var _ Store = (*SQLStore)(nil)
