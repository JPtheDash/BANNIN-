package scheduler

import (
	"context"
	"sync"
)

// Map runs fn over every item concurrently, with at most workers
// goroutines in flight, and returns the outputs in input order —
// callers can rely on results[i] corresponding to items[i] regardless
// of completion order. workers <= 0 (or more workers than items) means
// one goroutine per item, the right default for scanner plugins, which
// spend their time waiting on external tool subprocesses.
//
// Map itself never abandons an item: cancellation is fn's job (the
// scanner plugins run tools via exec.CommandContext, which kills the
// subprocess when ctx is cancelled), so every item still yields an
// output describing what happened to it.
func Map[In, Out any](ctx context.Context, workers int, items []In, fn func(context.Context, In) Out) []Out {
	if len(items) == 0 {
		return nil
	}
	if workers <= 0 || workers > len(items) {
		workers = len(items)
	}

	out := make([]Out, len(items))
	indexes := make(chan int)

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for i := range indexes {
				out[i] = fn(ctx, items[i])
			}
		}()
	}

	for i := range items {
		indexes <- i
	}
	close(indexes)
	wg.Wait()

	return out
}
