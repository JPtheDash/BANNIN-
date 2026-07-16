package config

import (
	"errors"
	"fmt"

	"github.com/spf13/viper"
)

// Config is the root BANNIN configuration, shaped after
// configs/bannin.example.yaml.
type Config struct {
	Scan    ScanConfig    `mapstructure:"scan"`
	Report  ReportConfig  `mapstructure:"report"`
	Policy  PolicyConfig  `mapstructure:"policy"`
	Storage StorageConfig `mapstructure:"storage"`
	Logging LoggingConfig `mapstructure:"logging"`
}

type ScanConfig struct {
	Target  string   `mapstructure:"target"`
	Plugins []string `mapstructure:"plugins"`
}

type ReportConfig struct {
	Formats   []string `mapstructure:"formats"`
	OutputDir string   `mapstructure:"output_dir"`
}

type PolicyConfig struct {
	FailOnSeverity string `mapstructure:"fail_on_severity"`
}

type StorageConfig struct {
	Driver string `mapstructure:"driver"`
	DSN    string `mapstructure:"dsn"`
}

type LoggingConfig struct {
	Level string `mapstructure:"level"`
}

var validSeverities = map[string]bool{
	"low": true, "medium": true, "high": true, "critical": true,
}

var validStorageDrivers = map[string]bool{
	"sqlite": true, "postgres": true,
}

var validLogLevels = map[string]bool{
	"debug": true, "info": true, "warn": true, "error": true,
}

// Load reads BANNIN configuration from the given YAML file path, layered
// over built-in defaults. If path is empty, Load looks for ./bannin.yaml
// and falls back to defaults alone when no such file exists.
func Load(path string) (*Config, error) {
	v := viper.New()
	setDefaults(v)
	v.SetConfigType("yaml")

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("config: reading %s: %w", path, err)
		}
	} else {
		v.SetConfigName("bannin")
		v.AddConfigPath(".")
		if err := v.ReadInConfig(); err != nil {
			var notFound viper.ConfigFileNotFoundError
			if !errors.As(err, &notFound) {
				return nil, fmt.Errorf("config: %w", err)
			}
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("scan.target", ".")
	v.SetDefault("scan.plugins", []string{"semgrep", "osv", "trivy", "gitleaks"})
	v.SetDefault("report.formats", []string{"html", "json", "sarif"})
	v.SetDefault("report.output_dir", "./bannin-report")
	v.SetDefault("policy.fail_on_severity", "high")
	v.SetDefault("storage.driver", "sqlite")
	v.SetDefault("storage.dsn", "./bannin.db")
	v.SetDefault("logging.level", "info")
}

// Validate checks that the configured values are within the set BANNIN
// currently understands.
func (c *Config) Validate() error {
	if c.Policy.FailOnSeverity != "" && !validSeverities[c.Policy.FailOnSeverity] {
		return fmt.Errorf("config: policy.fail_on_severity %q must be one of low, medium, high, critical", c.Policy.FailOnSeverity)
	}
	if c.Storage.Driver != "" && !validStorageDrivers[c.Storage.Driver] {
		return fmt.Errorf("config: storage.driver %q must be one of sqlite, postgres", c.Storage.Driver)
	}
	if c.Logging.Level != "" && !validLogLevels[c.Logging.Level] {
		return fmt.Errorf("config: logging.level %q must be one of debug, info, warn, error", c.Logging.Level)
	}
	return nil
}
