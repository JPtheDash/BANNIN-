// Package storage persists scan reports to SQLite so `bannin serve`
// can show history instead of only the most recent scan. It is a pure
// persistence adapter: it depends on internal/report for the Report
// type and nothing else in internal/ — internal/dashboard depends on
// it (via SQLStore, defined there) to keep the direction of dependency
// pointing from HTTP-facing code toward storage, never back.
//
// Each report is stored as one row: indexed columns for cheap listing
// (generated_at, target, total, by_severity) plus the full report as a
// JSON blob. A local CLI tool's scan history is small — hundreds to
// low thousands of rows — so this is simpler and easier to keep
// schema-compatible with report.json than normalizing findings into
// their own table would be, at a scale where that cost buys nothing.
package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/jyotidash/bannin/internal/report"
	"github.com/jyotidash/bannin/pkg/plugin"
)

// ErrNotFound indicates no report exists with the requested id (Get)
// or at all (Latest on an empty store).
var ErrNotFound = errors.New("storage: no matching report")

// Meta is a report's listing metadata — cheap to fetch in bulk because
// it never touches the findings JSON blob.
type Meta struct {
	ID          int64
	GeneratedAt time.Time
	Target      string
	Total       int
	BySeverity  map[plugin.Severity]int
}

// Store persists Reports to a SQLite database.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS reports (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	generated_at TEXT    NOT NULL,
	target       TEXT    NOT NULL,
	total        INTEGER NOT NULL,
	by_severity  TEXT    NOT NULL,
	report       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_generated_at ON reports(generated_at);
`

// Open opens (creating if necessary) the SQLite database at dsn and
// ensures its schema exists. driver must be "sqlite" — it is only
// accepted as a parameter, rather than assumed, so callers get one
// clear error site instead of every caller needing to know which
// drivers storage currently supports.
func Open(driver, dsn string) (*Store, error) {
	if driver != "sqlite" {
		return nil, fmt.Errorf("storage: driver %q not implemented (only \"sqlite\" is)", driver)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: opening %s: %w", dsn, err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: creating schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Save persists r as a new row and returns its id.
func (s *Store) Save(r report.Report) (int64, error) {
	total := len(r.Findings)
	bySeverity := make(map[plugin.Severity]int)
	for _, f := range r.Findings {
		bySeverity[f.Severity]++
	}
	bySeverityJSON, err := json.Marshal(bySeverity)
	if err != nil {
		return 0, fmt.Errorf("storage: encoding severity counts: %w", err)
	}
	reportJSON, err := json.Marshal(r)
	if err != nil {
		return 0, fmt.Errorf("storage: encoding report: %w", err)
	}

	res, err := s.db.Exec(
		`INSERT INTO reports (generated_at, target, total, by_severity, report) VALUES (?, ?, ?, ?, ?)`,
		r.GeneratedAt.Format(time.RFC3339), r.Target, total, string(bySeverityJSON), string(reportJSON),
	)
	if err != nil {
		return 0, fmt.Errorf("storage: saving report: %w", err)
	}
	return res.LastInsertId()
}

// List returns up to limit reports' metadata, most recent first. A
// non-positive limit returns all reports.
func (s *Store) List(limit int) ([]Meta, error) {
	query := `SELECT id, generated_at, target, total, by_severity FROM reports ORDER BY generated_at DESC, id DESC`
	args := []any{}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: listing reports: %w", err)
	}
	defer rows.Close()

	var metas []Meta
	for rows.Next() {
		var m Meta
		var generatedAt, bySeverityJSON string
		if err := rows.Scan(&m.ID, &generatedAt, &m.Target, &m.Total, &bySeverityJSON); err != nil {
			return nil, fmt.Errorf("storage: reading report row: %w", err)
		}
		m.GeneratedAt, err = time.Parse(time.RFC3339, generatedAt)
		if err != nil {
			return nil, fmt.Errorf("storage: parsing generated_at: %w", err)
		}
		if err := json.Unmarshal([]byte(bySeverityJSON), &m.BySeverity); err != nil {
			return nil, fmt.Errorf("storage: parsing severity counts: %w", err)
		}
		metas = append(metas, m)
	}
	return metas, rows.Err()
}

// Get returns the full report stored under id.
func (s *Store) Get(id int64) (report.Report, error) {
	var reportJSON string
	err := s.db.QueryRow(`SELECT report FROM reports WHERE id = ?`, id).Scan(&reportJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return report.Report{}, ErrNotFound
	}
	if err != nil {
		return report.Report{}, fmt.Errorf("storage: fetching report %d: %w", id, err)
	}

	var r report.Report
	if err := json.Unmarshal([]byte(reportJSON), &r); err != nil {
		return report.Report{}, fmt.Errorf("storage: parsing report %d: %w", id, err)
	}
	return r, nil
}

// Latest returns the most recently saved report.
func (s *Store) Latest() (report.Report, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM reports ORDER BY generated_at DESC, id DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return report.Report{}, ErrNotFound
	}
	if err != nil {
		return report.Report{}, fmt.Errorf("storage: finding latest report: %w", err)
	}
	return s.Get(id)
}
