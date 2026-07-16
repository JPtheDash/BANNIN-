package main

import (
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/jyotidash/bannin/api/server"
	"github.com/jyotidash/bannin/internal/auth"
	"github.com/jyotidash/bannin/internal/config"
	"github.com/jyotidash/bannin/internal/dashboard"
	"github.com/jyotidash/bannin/internal/logging"
	"github.com/jyotidash/bannin/internal/storage"
)

var generateToken bool

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the dashboard API over HTTP",
	Long: `Serve starts BANNIN's dashboard JSON API, reading the most recent
report from report.output_dir (run "bannin scan" first). It does not run
scans itself.

Set server.auth_token in bannin.yaml (or the BANNIN_AUTH_TOKEN env var)
to require a Bearer credential on every request except /healthz. Use
--generate-token to print a fresh random one.

With storage.driver: sqlite (the default), scan history is served from
that database — every scan "bannin scan" has recorded, not just the
last one. Any other driver falls back to report.output_dir's
report.json, which only ever holds the most recent scan.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if generateToken {
			token, err := auth.GenerateToken()
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), token)
			return nil
		}

		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}

		logger, err := logging.New(cfg.Logging.Level, nil)
		if err != nil {
			return err
		}
		defer logger.Sync()

		if cfg.Server.AuthToken == "" {
			logger.Warn("server.auth_token is not set — the dashboard API is unauthenticated; anyone who can reach this address can read scan findings")
		}

		var store dashboard.Store
		historyEnabled := cfg.Storage.Driver == "sqlite"
		if historyEnabled {
			db, err := storage.Open(cfg.Storage.Driver, cfg.Storage.DSN)
			if err != nil {
				return err
			}
			defer db.Close()
			store = dashboard.NewSQLStore(db)
		} else {
			if cfg.Storage.Driver != "" {
				logger.Warn("storage driver not yet implemented; scan history unavailable, serving only the most recent report",
					zap.String("driver", cfg.Storage.Driver))
			}
			store = dashboard.NewFileStore(cfg.Report.OutputDir)
		}
		srv := server.New(store, logger, cfg.Server.AuthToken)

		addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
		logger.Info("dashboard API starting", zap.String("addr", addr), zap.String("report_dir", cfg.Report.OutputDir),
			zap.Bool("auth_enabled", cfg.Server.AuthToken != ""), zap.Bool("history_enabled", historyEnabled))
		fmt.Fprintf(cmd.OutOrStdout(), "Dashboard API listening on http://%s\n", addr)

		return http.ListenAndServe(addr, srv.Handler())
	},
}

func init() {
	serveCmd.Flags().BoolVar(&generateToken, "generate-token", false, "print a random auth token and exit, instead of starting the server")
}
