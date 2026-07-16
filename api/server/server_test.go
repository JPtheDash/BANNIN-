package server_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jyotidash/bannin/api/server"
	"github.com/jyotidash/bannin/internal/dashboard"
	"github.com/jyotidash/bannin/internal/report"
	"github.com/jyotidash/bannin/pkg/plugin"
)

// fakeStore is a dashboard.Store test double.
type fakeStore struct {
	report  report.Report
	err     error
	history []dashboard.HistoryEntry
	byID    map[int64]report.Report
}

func (s fakeStore) Latest() (report.Report, error) { return s.report, s.err }

func (s fakeStore) History(limit int) ([]dashboard.HistoryEntry, error) {
	if s.err != nil {
		return nil, s.err
	}
	if limit > 0 && limit < len(s.history) {
		return s.history[:limit], nil
	}
	return s.history, nil
}

func (s fakeStore) Get(id int64) (report.Report, error) {
	if s.err != nil {
		return report.Report{}, s.err
	}
	r, ok := s.byID[id]
	if !ok {
		return report.Report{}, dashboard.ErrNoReport
	}
	return r, nil
}

func (s fakeStore) Save(r report.Report) (int64, error) {
	if s.err != nil {
		return 0, s.err
	}
	return 0, nil
}

func TestHealthz(t *testing.T) {
	srv := httptest.NewServer(server.New(fakeStore{}, nil, "").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200", resp.StatusCode)
	}
}

func TestReportEndpoint(t *testing.T) {
	findings := []plugin.Finding{
		{ID: "1", Scanner: "semgrep", RuleID: "eval", Title: "eval", Severity: plugin.SeverityHigh,
			Location: plugin.Location{Path: "app.py"}},
	}
	store := fakeStore{report: report.New("./demo", []string{"semgrep"}, findings)}
	srv := httptest.NewServer(server.New(store, nil, "").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/report")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/report = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var got report.Report
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if got.Target != "./demo" || len(got.Findings) != 1 {
		t.Errorf("decoded report = %+v, want the store's report", got)
	}
}

func TestSummaryEndpoint(t *testing.T) {
	findings := []plugin.Finding{
		{ID: "1", Scanner: "gitleaks", RuleID: "aws-key", Title: "secret", Severity: plugin.SeverityHigh,
			Location: plugin.Location{Path: ".env"}},
	}
	store := fakeStore{report: report.New(".", nil, findings)}
	srv := httptest.NewServer(server.New(store, nil, "").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/summary")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got dashboard.Summary
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if got.Total != 1 || len(got.TopRisks) != 1 {
		t.Errorf("decoded summary = %+v, want total 1", got)
	}
}

func TestReportEndpointNoReportYet(t *testing.T) {
	store := fakeStore{err: dashboard.ErrNoReport}
	srv := httptest.NewServer(server.New(store, nil, "").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/report")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /api/v1/report with no scan yet = %d, want 404", resp.StatusCode)
	}
}

func TestReportEndpointStoreFailure(t *testing.T) {
	store := fakeStore{err: errors.New("disk on fire")}
	srv := httptest.NewServer(server.New(store, nil, "").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/report")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("GET /api/v1/report on store failure = %d, want 500", resp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] == "disk on fire" {
		t.Error("internal store error details leaked into the HTTP response body")
	}
}

func TestAuthRejectsMissingOrWrongToken(t *testing.T) {
	store := fakeStore{report: report.New(".", nil, nil)}
	srv := httptest.NewServer(server.New(store, nil, "correct-token").Handler())
	defer srv.Close()

	cases := []struct {
		name   string
		header string
	}{
		{"no header", ""},
		{"wrong token", "Bearer wrong-token"},
		{"missing Bearer prefix", "correct-token"},
	}
	for _, c := range cases {
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/report", nil)
		if c.header != "" {
			req.Header.Set("Authorization", c.header)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", c.name, resp.StatusCode)
		}
		if resp.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: missing WWW-Authenticate header", c.name)
		}
	}
}

func TestAuthAcceptsCorrectToken(t *testing.T) {
	store := fakeStore{report: report.New(".", nil, nil)}
	srv := httptest.NewServer(server.New(store, nil, "correct-token").Handler())
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/report", nil)
	req.Header.Set("Authorization", "Bearer correct-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 with a correct token", resp.StatusCode)
	}
}

func TestAuthHealthzAlwaysOpen(t *testing.T) {
	srv := httptest.NewServer(server.New(fakeStore{}, nil, "correct-token").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz with auth enabled = %d, want 200 (healthz stays open)", resp.StatusCode)
	}
}

func TestAuthDisabledWhenTokenEmpty(t *testing.T) {
	store := fakeStore{report: report.New(".", nil, nil)}
	srv := httptest.NewServer(server.New(store, nil, "").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/report")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /api/v1/report with no auth_token configured = %d, want 200 (no credential required)", resp.StatusCode)
	}
}

func TestHistoryEndpoint(t *testing.T) {
	store := fakeStore{history: []dashboard.HistoryEntry{
		{ID: 2, Target: "./demo", Total: 3},
		{ID: 1, Target: "./demo", Total: 5},
	}}
	srv := httptest.NewServer(server.New(store, nil, "").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/history")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/history = %d, want 200", resp.StatusCode)
	}

	var got []dashboard.HistoryEntry
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(got) != 2 || got[0].ID != 2 {
		t.Errorf("decoded history = %+v, want the store's entries in order", got)
	}
}

func TestHistoryEndpointEmptyIsArrayNotNull(t *testing.T) {
	store := fakeStore{history: nil}
	srv := httptest.NewServer(server.New(store, nil, "").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/history")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(body)) != "[]" {
		t.Errorf("empty history body = %q, want []", body)
	}
}

func TestHistoryEndpointRespectsLimit(t *testing.T) {
	store := fakeStore{history: []dashboard.HistoryEntry{{ID: 3}, {ID: 2}, {ID: 1}}}
	srv := httptest.NewServer(server.New(store, nil, "").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/history?limit=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got []dashboard.HistoryEntry
	json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 1 {
		t.Errorf("GET /api/v1/history?limit=1 returned %d entries, want 1", len(got))
	}
}

func TestGetReportEndpoint(t *testing.T) {
	rep := report.New("./demo", []string{"semgrep"}, []plugin.Finding{
		{ID: "1", Scanner: "semgrep", RuleID: "eval", Title: "eval", Severity: plugin.SeverityHigh,
			Location: plugin.Location{Path: "app.py"}},
	})
	store := fakeStore{byID: map[int64]report.Report{7: rep}}
	srv := httptest.NewServer(server.New(store, nil, "").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/reports/7")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/reports/7 = %d, want 200", resp.StatusCode)
	}
	var got report.Report
	json.NewDecoder(resp.Body).Decode(&got)
	if got.Target != "./demo" || len(got.Findings) != 1 {
		t.Errorf("decoded report = %+v, want the store's report for id 7", got)
	}
}

func TestGetReportEndpointUnknownID(t *testing.T) {
	store := fakeStore{byID: map[int64]report.Report{}}
	srv := httptest.NewServer(server.New(store, nil, "").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/reports/999")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /api/v1/reports/999 = %d, want 404", resp.StatusCode)
	}
}

func TestGetReportEndpointNonIntegerID(t *testing.T) {
	store := fakeStore{byID: map[int64]report.Report{}}
	srv := httptest.NewServer(server.New(store, nil, "").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/reports/not-a-number")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("GET /api/v1/reports/not-a-number = %d, want 400", resp.StatusCode)
	}
}

func TestTriggerScanRejectsEmptyTarget(t *testing.T) {
	srv := httptest.NewServer(server.New(fakeStore{}, nil, "").Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/scan", "application/json", strings.NewReader(`{"target":""}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /api/v1/scan with empty target = %d, want 400", resp.StatusCode)
	}
}

func TestTriggerScanRejectsZapAgainstNonURL(t *testing.T) {
	srv := httptest.NewServer(server.New(fakeStore{}, nil, "").Handler())
	defer srv.Close()

	body := `{"target":"./some/path","plugins":["zap"]}`
	resp, err := http.Post(srv.URL+"/api/v1/scan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /api/v1/scan with zap + non-URL target = %d, want 400", resp.StatusCode)
	}
}

// TestTriggerScanRunsInBackgroundAndReportsFailure exercises the full
// on-demand path — 202 with a pollable job id, background execution,
// and the job settling to "failed" — using an unregistered plugin name
// so the assertion doesn't depend on any scanner binary being on PATH.
func TestTriggerScanRunsInBackgroundAndReportsFailure(t *testing.T) {
	srv := httptest.NewServer(server.New(fakeStore{}, nil, "").Handler())
	defer srv.Close()

	body := `{"target":"./testdata","plugins":["no-such-plugin"]}`
	resp, err := http.Post(srv.URL+"/api/v1/scan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /api/v1/scan = %d, want 202", resp.StatusCode)
	}
	var job struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if job.Status != "running" {
		t.Errorf("initial job status = %q, want %q", job.Status, "running")
	}

	deadline := time.Now().Add(5 * time.Second)
	var status string
	for time.Now().Before(deadline) {
		r, err := http.Get(srv.URL + "/api/v1/scans/" + job.ID)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		json.NewDecoder(r.Body).Decode(&got)
		r.Body.Close()
		status = got.Status
		if status != "running" {
			if status != "failed" {
				t.Errorf("job status = %q, want %q (unregistered plugin should fail Resolve)", status, "failed")
			}
			if !strings.Contains(got.Error, "no-such-plugin") {
				t.Errorf("job error = %q, want it to name the unknown plugin", got.Error)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job never left \"running\" within the test deadline (last status %q)", status)
}
