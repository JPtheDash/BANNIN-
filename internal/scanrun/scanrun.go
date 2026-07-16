// Package scanrun holds the findings pipeline shared by every caller that
// triggers a scan: `bannin scan` (cmd/bannin) and the on-demand scan
// endpoint (api/server). Keeping it in one place means the CLI and the
// dashboard's "scan a target" button can never drift apart on what
// merge/normalize/dedupe/correlate/risk-score actually does.
package scanrun

import (
	"context"

	"go.uber.org/zap"

	"github.com/jyotidash/bannin/internal/correlation"
	"github.com/jyotidash/bannin/internal/report"
	"github.com/jyotidash/bannin/internal/scanner"
	"github.com/jyotidash/bannin/pkg/plugin"
)

// Run resolves plugins, executes them against target, and reduces the
// results through the full findings pipeline (merge -> normalize
// severities -> normalize paths -> dedupe -> reconcile aliases -> sort
// -> risk-score via report.New) into one Report. The returned bool
// reports whether any plugin failed to run — callers that gate on it
// (like the CLI's exit code) can still inspect the partial Report.
// A nil logger is treated as a no-op logger.
func Run(ctx context.Context, target string, plugins []string, logger *zap.Logger) (report.Report, bool, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	logger.Info("scan starting", zap.String("target", target), zap.Strings("plugins", plugins))

	mgr := scanner.NewManager(nil)
	scanners, err := mgr.Resolve(plugins)
	if err != nil {
		return report.Report{}, false, err
	}

	results := mgr.Scan(ctx, target, scanners)
	var failed bool
	pluginRuns := make([]report.PluginRun, len(results))
	for i, r := range results {
		run := report.PluginRun{Name: r.Plugin, Success: r.Err == nil, Findings: len(r.Findings), DurationMS: r.Duration.Milliseconds()}
		if r.Err != nil {
			failed = true
			run.Error = r.Err.Error()
			logger.Error("plugin failed", zap.String("plugin", r.Plugin), zap.Error(r.Err))
		} else {
			logger.Info("plugin finished", zap.String("plugin", r.Plugin), zap.Int("findings", len(r.Findings)))
		}
		pluginRuns[i] = run
	}
	findings := scanner.Collect(results)
	findings = plugin.NormalizeFindings(findings)
	correlation.NormalizePaths(findings, target)
	before := len(findings)
	findings = correlation.Dedupe(findings)
	if removed := before - len(findings); removed > 0 {
		logger.Info("deduplicated findings", zap.Int("removed", removed))
	}
	before = len(findings)
	findings = correlation.ReconcileAliases(findings)
	if merged := before - len(findings); merged > 0 {
		logger.Info("reconciled alias findings", zap.Int("merged", merged))
	}
	plugin.SortFindings(findings)

	rep := report.New(target, plugins, findings).WithPluginRuns(pluginRuns)
	return rep, failed, nil
}
