package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
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

func TestAppendProgressDedupesAndBounds(t *testing.T) {
	j := &scanJob{}

	// Consecutive duplicates collapse to one entry.
	j.appendProgress("Spider 10%")
	j.appendProgress("Spider 10%")
	if len(j.Progress) != 1 {
		t.Fatalf("consecutive duplicate lines = %d entries, want 1", len(j.Progress))
	}

	// The tail is bounded to the most recent maxProgressLines.
	for i := 0; i < maxProgressLines+15; i++ {
		j.appendProgress("line-" + strconv.Itoa(i))
	}
	if len(j.Progress) != maxProgressLines {
		t.Fatalf("progress length = %d, want it capped at %d", len(j.Progress), maxProgressLines)
	}
	last := j.Progress[len(j.Progress)-1]
	if want := "line-" + strconv.Itoa(maxProgressLines+15-1); last != want {
		t.Errorf("last kept line = %q, want the most recent %q", last, want)
	}
}

// TestViewCopiesProgress guards against the status handler aliasing the
// job's live slice — a concurrent progress append must not mutate a view
// already handed to a responder.
func TestViewCopiesProgress(t *testing.T) {
	j := &scanJob{Status: "running"}
	j.appendProgress("a")
	v := j.view()
	j.appendProgress("b")
	if len(v.Progress) != 1 || v.Progress[0] != "a" {
		t.Errorf("view progress = %v, want a stable copy [a]", v.Progress)
	}
}
