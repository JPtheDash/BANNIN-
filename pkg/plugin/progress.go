package plugin

import "context"

// ProgressFunc receives one human-readable progress line from a running
// scanner (e.g. ZAP's "Job spider started" / active-scan percentage). It
// must be safe to call from the plugin's own goroutine and should return
// quickly — a slow sink slows the scan.
type ProgressFunc func(line string)

type progressKey struct{}

// WithProgress attaches a progress sink to ctx so a long-running plugin
// can stream what it's doing (which the dashboard surfaces instead of an
// opaque "running"). A nil fn leaves ctx unchanged. This is intentionally
// carried on the context rather than added to the Scanner.Run signature:
// progress is an optional, cross-cutting concern that only some plugins
// emit, and threading it through every plugin and the orchestrator would
// churn code that doesn't care about it.
func WithProgress(ctx context.Context, fn ProgressFunc) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, progressKey{}, fn)
}

// Progress returns the sink attached by WithProgress, or nil if none.
// Callers should nil-check before use (or use Report, which does).
func Progress(ctx context.Context) ProgressFunc {
	fn, _ := ctx.Value(progressKey{}).(ProgressFunc)
	return fn
}

// Report sends line to ctx's progress sink if one is attached, and is a
// no-op otherwise — the convenient form for plugins that don't want to
// nil-check.
func Report(ctx context.Context, line string) {
	if fn := Progress(ctx); fn != nil {
		fn(line)
	}
}
