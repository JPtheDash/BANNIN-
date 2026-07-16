// Package server exposes BANNIN's scan report data over HTTP for the
// dashboard (web UI, Milestone 19) and any future integrations. It is
// an adapter in the hexagonal sense: it depends on internal/dashboard
// through the Store interface, never on how reports are actually
// stored, so Milestone 15 (persistent scan history) can change the
// backing store without this package changing.
//
// The server can also front the built dashboard on its own origin (see
// WithStaticDir), so the whole tool runs as one process on one port
// with no CORS to configure — the browser sees the UI and the API as
// same-origin. (During frontend development the vite dev server proxies
// instead, see web/vite.config.ts.) Bind server.host to 127.0.0.1 (the
// default) unless you already have another way to restrict access, and
// set server.auth_token (Milestone 20) if the port is reachable by
// anyone you don't trust.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/jyotidash/bannin/internal/auth"
	"github.com/jyotidash/bannin/internal/dashboard"
	"github.com/jyotidash/bannin/internal/scanrun"
)

// defaultHistoryLimit caps GET /api/v1/history when the caller doesn't
// specify ?limit — enough for a dashboard's history panel without a
// single request pulling a database's entire scan record.
const defaultHistoryLimit = 20

// Server serves the dashboard JSON API.
type Server struct {
	store     dashboard.Store
	logger    *zap.Logger
	authToken string

	jobsMu   sync.Mutex
	jobs     map[string]*scanJob
	jobSeq   atomic.Int64
	scanning atomic.Bool // single-flight: one on-demand scan at a time

	// staticDir, if non-empty, is a directory of built dashboard assets
	// served on the same origin as the API (see WithStaticDir).
	staticDir string
}

// New returns a Server reading report data from store. A nil logger
// disables request-error logging. authToken, if non-empty, is required
// as a Bearer credential on every request except /healthz; an empty
// authToken disables auth entirely — an explicit choice for local
// development, not a silent default (`bannin serve` warns loudly when
// it's unset).
func New(store dashboard.Store, logger *zap.Logger, authToken string) *Server {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Server{store: store, logger: logger, authToken: authToken, jobs: make(map[string]*scanJob)}
}

// WithStaticDir makes Handler also serve the built dashboard assets in
// dir on the same origin as the API — one process, one port, no
// separate dev server. Returns the receiver for chaining. An empty dir
// leaves the server API-only (the previous behavior).
func (s *Server) WithStaticDir(dir string) *Server {
	s.staticDir = dir
	return s
}

// Handler returns the API's http.Handler, ready to pass to
// http.ListenAndServe or httptest.NewServer.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/v1/report", s.handleReport)
	mux.HandleFunc("GET /api/v1/summary", s.handleSummary)
	mux.HandleFunc("GET /api/v1/history", s.handleHistory)
	mux.HandleFunc("GET /api/v1/reports/{id}", s.handleGetReport)
	mux.HandleFunc("POST /api/v1/scan", s.handleTriggerScan)
	mux.HandleFunc("GET /api/v1/scans/{id}", s.handleScanStatus)
	// The built dashboard is served as the catch-all so any route the
	// API doesn't own (/, /findings, static assets) goes to the SPA. A
	// more specific pattern always wins in net/http's mux, so the API
	// routes above are unaffected.
	if s.staticDir != "" {
		mux.Handle("/", s.spaHandler())
	}
	return s.requireAuth(mux)
}

// spaHandler serves files from staticDir, falling back to index.html
// for any path that isn't an existing file so client-side routing
// (react-router) works on deep links and page reloads.
func (s *Server) spaHandler() http.Handler {
	fs := http.FileServer(http.Dir(s.staticDir))
	index := filepath.Join(s.staticDir, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// filepath.Join cleans the path, so a served file can never
		// escape staticDir; anything that doesn't resolve to a real file
		// falls through to index.html (never an arbitrary path).
		p := filepath.Join(s.staticDir, filepath.Clean(r.URL.Path))
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			fs.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, index)
	})
}

// requireAuth enforces the Bearer token on every /api/ request. The
// health check and the static dashboard assets stay open: /healthz so
// load balancers and `docker healthcheck` can confirm the process is up
// without a credential, and the assets because the SPA shell reveals
// nothing on its own — every request for actual findings goes through
// the protected /api/ routes.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authToken == "" || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !auth.Verify(s.authToken, presented) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="bannin"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	rep, err := s.store.Latest()
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	rep, err := s.store.Latest()
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dashboard.Summarize(rep))
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	limit := defaultHistoryLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}

	entries, err := s.store.History(limit)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	if entries == nil {
		entries = []dashboard.HistoryEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleGetReport(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id must be an integer"})
		return
	}

	rep, err := s.store.Get(id)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// defaultPathPlugins mirrors internal/config's scan.plugins default —
// the on-demand endpoint applies the same default when the caller
// targets a filesystem path and doesn't name plugins explicitly.
var defaultPathPlugins = []string{"semgrep", "osv", "trivy", "gitleaks"}

// scanJob tracks one on-demand scan triggered via POST /api/v1/scan,
// so the dashboard can poll GET /api/v1/scans/{id} while ZAP (or any
// other plugin) is still running in the background.
type scanJob struct {
	ID        string
	Target    string
	Plugins   []string
	Status    string // "running", "done", "failed"
	Error     string
	ReportID  int64
	StartedAt time.Time
}

type scanRequest struct {
	Target  string   `json:"target"`
	Plugins []string `json:"plugins"`
}

type scanJobView struct {
	ID       string `json:"id"`
	Target   string `json:"target"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
	ReportID *int64 `json:"report_id,omitempty"`
}

func (j *scanJob) view() scanJobView {
	v := scanJobView{ID: j.ID, Target: j.Target, Status: j.Status, Error: j.Error}
	if j.Status == "done" {
		id := j.ReportID
		v.ReportID = &id
	}
	return v
}

// handleTriggerScan starts a scan against a caller-supplied target in
// the background and returns immediately with a job id to poll — a
// ZAP scan of a real URL can run for minutes, far past what an HTTP
// client should block on. Only one on-demand scan runs at a time
// (a scan job already in flight gets a 409, not a queued second run),
// since these share the process's storage handle and there is no
// concurrency story yet for that.
func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target is required"})
		return
	}

	isURL := strings.HasPrefix(req.Target, "http://") || strings.HasPrefix(req.Target, "https://")
	plugins := req.Plugins
	if len(plugins) == 0 {
		if isURL {
			plugins = []string{"zap"}
		} else {
			plugins = defaultPathPlugins
		}
	}
	for _, p := range plugins {
		if p == "zap" && !isURL {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "zap requires target to be a running app's http(s) URL"})
			return
		}
	}

	if !s.scanning.CompareAndSwap(false, true) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a scan is already in progress; wait for it to finish"})
		return
	}

	job := &scanJob{
		ID:        fmt.Sprintf("job-%d", s.jobSeq.Add(1)),
		Target:    req.Target,
		Plugins:   plugins,
		Status:    "running",
		StartedAt: time.Now(),
	}
	s.jobsMu.Lock()
	s.jobs[job.ID] = job
	s.jobsMu.Unlock()

	go s.runScanJob(job)

	writeJSON(w, http.StatusAccepted, job.view())
}

// runScanJob executes job in the background using the same findings
// pipeline `bannin scan` uses (internal/scanrun), persists the result
// through the same Store the rest of the dashboard reads from, and
// updates job's status for handleScanStatus to report. It always
// releases the single-flight scanning gate, even on panic recovery
// from scanrun.Run's own plugin isolation — the gate must never stay
// stuck held.
func (s *Server) runScanJob(job *scanJob) {
	defer s.scanning.Store(false)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	rep, pluginsFailed, err := scanrun.Run(ctx, job.Target, job.Plugins, s.logger)

	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
		s.logger.Error("on-demand scan failed", zap.String("job", job.ID), zap.Error(err))
		return
	}

	id, saveErr := s.store.Save(rep)
	if saveErr != nil {
		job.Status = "failed"
		job.Error = fmt.Sprintf("scan completed but saving it failed: %v", saveErr)
		s.logger.Error("saving on-demand scan", zap.String("job", job.ID), zap.Error(saveErr))
		return
	}

	job.Status = "done"
	job.ReportID = id
	if pluginsFailed {
		job.Error = "one or more plugins failed; see the report's scanner health for details"
	}
	s.logger.Info("on-demand scan saved", zap.String("job", job.ID), zap.Int64("report_id", id))
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.jobsMu.Lock()
	job, ok := s.jobs[id]
	s.jobsMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such scan job"})
		return
	}
	writeJSON(w, http.StatusOK, job.view())
}

func (s *Server) writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, dashboard.ErrNoReport) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	s.logger.Error("dashboard store error", zap.Error(err))
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error retrieving report"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Encoding failures here mean the connection is already gone or the
	// body is a Go bug, not something a client response can fix; the
	// status code is already committed, so there is nothing more to do
	// but drop the error.
	_ = json.NewEncoder(w).Encode(body)
}
