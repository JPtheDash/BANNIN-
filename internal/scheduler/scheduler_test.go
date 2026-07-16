package scheduler_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jyotidash/bannin/internal/scheduler"
)

func TestMapPreservesInputOrder(t *testing.T) {
	items := []int{5, 3, 8, 1, 9, 2}

	// Sleep inversely to position so later items finish first — output
	// order must still match input order.
	got := scheduler.Map(context.Background(), 0, items, func(_ context.Context, n int) int {
		time.Sleep(time.Duration(len(items)-n) * time.Millisecond)
		return n * 10
	})

	for i, item := range items {
		if got[i] != item*10 {
			t.Fatalf("got[%d] = %d, want %d (order not preserved: %v)", i, got[i], item*10, got)
		}
	}
}

func TestMapRunsConcurrently(t *testing.T) {
	const n = 4
	const naptime = 100 * time.Millisecond

	start := time.Now()
	scheduler.Map(context.Background(), 0, make([]struct{}, n), func(context.Context, struct{}) struct{} {
		time.Sleep(naptime)
		return struct{}{}
	})
	elapsed := time.Since(start)

	// Sequential would take n*naptime (400ms); allow generous slack for
	// slow machines while still proving overlap happened.
	if elapsed >= (n-1)*naptime {
		t.Errorf("Map took %v for %d overlapping %v jobs; looks sequential", elapsed, n, naptime)
	}
}

func TestMapRespectsWorkerLimit(t *testing.T) {
	const workers = 2
	var inFlight, peak atomic.Int32

	scheduler.Map(context.Background(), workers, make([]struct{}, 8), func(context.Context, struct{}) struct{} {
		cur := inFlight.Add(1)
		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		inFlight.Add(-1)
		return struct{}{}
	})

	if got := peak.Load(); got > workers {
		t.Errorf("peak concurrency = %d, want <= %d", got, workers)
	}
}

func TestMapEmptyInput(t *testing.T) {
	got := scheduler.Map(context.Background(), 0, nil, func(context.Context, int) int { return 1 })
	if len(got) != 0 {
		t.Errorf("Map(nil) returned %v, want empty", got)
	}
}

func TestMapPassesContextThrough(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got := scheduler.Map(ctx, 0, []int{1, 2}, func(ctx context.Context, n int) error {
		return ctx.Err()
	})

	for i, err := range got {
		if err == nil {
			t.Errorf("job %d did not see the cancelled context", i)
		}
	}
}
