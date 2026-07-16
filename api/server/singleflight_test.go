package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleTriggerScanSingleFlight verifies the 409 rejection directly
// against the scanning gate rather than racing a real plugin's
// execution time — scanner subprocess speed varies by machine and
// installed tools, so a black-box test asserting "second concurrent
// POST returns 409" would be flaky. Living in package server (not
// server_test) lets it reach the unexported gate directly.
func TestHandleTriggerScanSingleFlight(t *testing.T) {
	s := New(nil, nil, "")
	s.scanning.Store(true) // simulate a scan already in flight

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(`{"target":"https://example.com","plugins":["zap"]}`))
	w := httptest.NewRecorder()
	s.handleTriggerScan(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 when a scan is already in flight", w.Code)
	}
}
