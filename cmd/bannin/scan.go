package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/jyotidash/bannin/internal/config"
	"github.com/jyotidash/bannin/internal/correlation"
	"github.com/jyotidash/bannin/internal/logging"
	"github.com/jyotidash/bannin/internal/policy"
	"github.com/jyotidash/bannin/internal/report"
	"github.com/jyotidash/bannin/internal/scanner"
	"github.com/jyotidash/bannin/pkg/plugin"
)

var (
	errScanPluginFailed = errors.New("scan: one or more plugins failed")
	errPolicyViolation  = errors.New("scan: policy violation: findings at or above fail_on_severity")
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run configured scanners against a target",
	Long: `Scan runs the configured security scanner plugins against a target,
merges their findings into one normalized, deduplicated, severity-sorted
collection, prints a summary, and writes report.json to the configured
report.output_dir (when "json" is among report.formats).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}

		logger, err := logging.New(cfg.Logging.Level, nil)
		if err != nil {
			return err
		}
		defer logger.Sync()

		logger.Info("scan starting",
			zap.String("target", cfg.Scan.Target),
			zap.Strings("plugins", cfg.Scan.Plugins),
		)

		mgr := scanner.NewManager(nil)
		scanners, err := mgr.Resolve(cfg.Scan.Plugins)
		if err != nil {
			logger.Error("scan aborted", zap.Error(err))
			return err
		}

		results := mgr.Scan(cmd.Context(), cfg.Scan.Target, scanners)
		var failed bool
		for _, r := range results {
			if r.Err != nil {
				failed = true
				logger.Error("plugin failed", zap.String("plugin", r.Plugin), zap.Error(r.Err))
				continue
			}
			logger.Info("plugin finished", zap.String("plugin", r.Plugin), zap.Int("findings", len(r.Findings)))
		}

		// The findings pipeline: merge -> normalize severities ->
		// normalize paths -> dedupe -> reconcile aliases -> sort. Every
		// downstream consumer (reports now; dashboard, risk scoring
		// later) sees this same collection. Paths normalize before the
		// correlation passes because both compare locations literally.
		findings := scanner.Collect(results)
		findings = plugin.NormalizeFindings(findings)
		correlation.NormalizePaths(findings, cfg.Scan.Target)
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

		rep := report.New(cfg.Scan.Target, cfg.Scan.Plugins, findings)
		report.Summary(cmd.OutOrStdout(), rep)

		writers := map[string]func(string, report.Report) (string, error){
			"json": report.WriteJSON,
			"html": report.WriteHTML,
		}
		fmt.Fprintln(cmd.OutOrStdout())
		for _, format := range cfg.Report.Formats {
			write, ok := writers[format]
			if !ok {
				logger.Warn("report format not yet implemented", zap.String("format", format))
				continue
			}
			path, err := write(cfg.Report.OutputDir, rep)
			if err != nil {
				logger.Error("writing report", zap.Error(err))
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Report written to %s\n", path)
		}

		// Policy gate. An empty fail_on_severity disables gating; the
		// config default is "high".
		var violated bool
		if cfg.Policy.FailOnSeverity != "" {
			decision, err := policy.Evaluate(findings, plugin.Severity(cfg.Policy.FailOnSeverity))
			if err != nil {
				return err
			}
			violated = decision.Failed()
			if violated {
				fmt.Fprintf(cmd.OutOrStdout(), "\nPolicy: FAIL — %d finding(s) at or above %s severity\n",
					len(decision.Violations), decision.Threshold)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "\nPolicy: PASS — no findings at or above %s severity\n",
					decision.Threshold)
			}
		}

		// A plugin that couldn't run outranks a policy verdict: CI must
		// not go green when part of the scan never happened.
		if failed {
			return errScanPluginFailed
		}
		if violated {
			return errPolicyViolation
		}
		return nil
	},
}
