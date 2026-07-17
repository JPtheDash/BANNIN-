package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/jyotidash/bannin/internal/config"
	"github.com/jyotidash/bannin/internal/logging"
	"github.com/jyotidash/bannin/internal/policy"
	"github.com/jyotidash/bannin/internal/report"
	"github.com/jyotidash/bannin/internal/scanner"
	"github.com/jyotidash/bannin/internal/scanrun"
	"github.com/jyotidash/bannin/internal/storage"
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
		applyPluginConfig(scanner.DefaultRegistry, cfg)

		logger, err := logging.New(cfg.Logging.Level, nil)
		if err != nil {
			return err
		}
		defer logger.Sync()

		rep, failed, err := scanrun.Run(cmd.Context(), cfg.Scan.Target, cfg.Scan.Plugins, logger)
		if err != nil {
			logger.Error("scan aborted", zap.Error(err))
			return err
		}
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

		// Scan history: best-effort. A storage hiccup shouldn't fail a
		// scan whose reports and policy gate already succeeded — it's
		// supplementary to the artifacts scan just produced, not part of
		// their contract.
		switch cfg.Storage.Driver {
		case "sqlite":
			if store, err := storage.Open(cfg.Storage.Driver, cfg.Storage.DSN); err != nil {
				logger.Error("opening scan history storage; scan not recorded to history", zap.Error(err))
			} else {
				id, err := store.Save(rep)
				store.Close()
				if err != nil {
					logger.Error("saving scan to history", zap.Error(err))
				} else {
					logger.Info("scan saved to history", zap.Int64("id", id))
				}
			}
		case "":
			// History disabled; nothing to do.
		default:
			logger.Warn("storage driver not yet implemented; scan not recorded to history", zap.String("driver", cfg.Storage.Driver))
		}

		// Policy gate. An empty fail_on_severity disables gating; the
		// config default is "high".
		var violated bool
		if cfg.Policy.FailOnSeverity != "" {
			findings := make([]plugin.Finding, len(rep.Findings))
			for i, f := range rep.Findings {
				findings[i] = f.Finding
			}
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
