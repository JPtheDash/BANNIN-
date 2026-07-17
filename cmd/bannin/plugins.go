package main

import (
	"github.com/jyotidash/bannin/internal/config"
	"github.com/jyotidash/bannin/internal/scanner"
	"github.com/jyotidash/bannin/plugins/checkov"
	"github.com/jyotidash/bannin/plugins/gitleaks"
	"github.com/jyotidash/bannin/plugins/osv"
	"github.com/jyotidash/bannin/plugins/semgrep"
	"github.com/jyotidash/bannin/plugins/trivy"
	"github.com/jyotidash/bannin/plugins/zap"
)

// registerPlugins wires concrete Scanner implementations into registry.
// This is the composition root: plugins/* depend only on pkg/plugin, so
// something outside them has to know both the plugin packages and
// internal/scanner to connect the two. That's cmd/bannin's job, not the
// plugins' or the manager's.
func registerPlugins(registry *scanner.Registry) {
	registry.Register(semgrep.New())
	registry.Register(osv.New())
	registry.Register(trivy.New())
	registry.Register(gitleaks.New())
	registry.Register(checkov.New())
	registry.Register(zap.New())
}

func init() {
	registerPlugins(scanner.DefaultRegistry)
}

// applyPluginConfig applies loaded configuration to already-registered
// plugins (registration happens in init, before any config is read).
// Currently only the ZAP plugin has runtime-configurable behavior — its
// scan depth. Call it after config.Load, before running a scan.
func applyPluginConfig(registry *scanner.Registry, cfg *config.Config) {
	if s, ok := registry.Lookup("zap"); ok {
		if z, ok := s.(*zap.Plugin); ok {
			z.SetMode(cfg.Zap.Mode)
		}
	}
}
