package main

import "github.com/spf13/cobra"

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "bannin",
	Short: "BANNIN is a DevSecOps orchestration platform",
	Long: `BANNIN runs security scanners (Semgrep, Trivy, OSV Scanner,
Gitleaks, Checkov, ZAP) through a common plugin interface, normalizes
their output into one finding model, correlates and risk-scores it, and
produces unified HTML/JSON/SARIF reports and a dashboard.`,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./bannin.yaml)")
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
}
