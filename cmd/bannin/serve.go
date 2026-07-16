package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/jyotidash/bannin/api/server"
	"github.com/jyotidash/bannin/internal/auth"
	"github.com/jyotidash/bannin/internal/config"
	"github.com/jyotidash/bannin/internal/dashboard"
	"github.com/jyotidash/bannin/internal/logging"
	"github.com/jyotidash/bannin/internal/storage"
)

// resolveWebDir picks the directory of built dashboard assets to serve.
// A configured path wins (and is used even if it's currently empty, so
// a typo surfaces as a 404 rather than silently serving nothing);
// otherwise it auto-detects the conventional ./web/dist. Returns ""
// when neither is present, leaving the server API-only.
func resolveWebDir(configured string) string {
	if configured != "" {
		return configured
	}
	if _, err := os.Stat(filepath.Join("web", "dist", "index.html")); err == nil {
		return filepath.Join("web", "dist")
	}
	return ""
}

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

		// Serve the built dashboard on the same origin as the API when
		// it's available, so the whole tool is one process on one port
		// (no separate dev server). Prefer the configured path; else
		// auto-detect the conventional web/dist next to the working dir.
		webDir := resolveWebDir(cfg.Server.WebDir)
		if webDir != "" {
			srv.WithStaticDir(webDir)
		}

		addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
		logger.Info("dashboard starting", zap.String("addr", addr), zap.String("report_dir", cfg.Report.OutputDir),
			zap.Bool("auth_enabled", cfg.Server.AuthToken != ""), zap.Bool("history_enabled", historyEnabled),
			zap.String("web_dir", webDir))
		if webDir != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "BANNIN dashboard: http://%s\n", addr)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Dashboard API listening on http://%s (no built UI found — run `npm run build` in web/, or use scripts/start-web.sh)\n", addr)
		}

		return http.ListenAndServe(addr, srv.Handler())
	},
}

func init() {
	serveCmd.Flags().BoolVar(&generateToken, "generate-token", false, "print a random auth token and exit, instead of starting the server")
}
