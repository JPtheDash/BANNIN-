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
	Server  ServerConfig  `mapstructure:"server"`
	Logging LoggingConfig `mapstructure:"logging"`
	Zap     ZapConfig     `mapstructure:"zap"`
}

type ScanConfig struct {
	Target  string   `mapstructure:"target"`
	Plugins []string `mapstructure:"plugins"`
}

// ZapConfig configures the OWASP ZAP (DAST) plugin. Mode selects scan
// depth: "quick" (the default) is a fast spider + light active scan;
// "full" drives ZAP's automation framework through the full active-scan
// policy, probing for injection-class vulnerabilities at the cost of a
// much longer, more aggressive scan. Empty means quick.
//
// Ajax adds ZAP's AJAX spider (a real headless browser crawl) to a full
// scan so JavaScript-heavy single-page apps get discovered — the plain
// spider only sees links in static HTML. Browser picks which headless
// browser it drives. Ajax is ignored in quick mode.
//
// Auth, when set, lets the scan reach pages behind a login. See
// ZapAuthConfig; it only applies to full mode.
type ZapConfig struct {
	Mode    string        `mapstructure:"mode"`
	Ajax    bool          `mapstructure:"ajax"`
	Browser string        `mapstructure:"browser"`
	Auth    ZapAuthConfig `mapstructure:"auth"`
}

// ZapAuthConfig describes how ZAP authenticates to the target so it can
// scan authenticated pages. Method picks the scheme:
//
//   - "form"    — POST username/password to LoginURL (classic web apps)
//   - "json"    — POST credentials as a JSON body (SPA/API backends)
//   - "header"  — send a static header (e.g. Authorization: Bearer …) on
//     every request (token/API auth); needs no login round-trip
//   - "browser" — drive a headless browser to fill and submit the login
//     form (JS-heavy apps); reuses the AJAX browser
//
// Credentials are secrets: prefer the BANNIN_ZAP_AUTH_PASSWORD and
// BANNIN_ZAP_AUTH_TOKEN environment variables over writing Password/Token
// into bannin.yaml. LoggedInRegex / LoggedOutRegex let ZAP tell whether a
// response is still authenticated so it can re-login when the session
// drops; supplying at least one sharply improves authenticated coverage.
type ZapAuthConfig struct {
	Method         string `mapstructure:"method"`
	LoginURL       string `mapstructure:"login_url"`
	Username       string `mapstructure:"username"`
	Password       string `mapstructure:"password"`
	UsernameField  string `mapstructure:"username_field"`
	PasswordField  string `mapstructure:"password_field"`
	Header         string `mapstructure:"header"`
	Token          string `mapstructure:"token"`
	LoggedInRegex  string `mapstructure:"logged_in_regex"`
	LoggedOutRegex string `mapstructure:"logged_out_regex"`
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

// ServerConfig configures the `bannin serve` dashboard API (Milestone
// 18). It reads reports from Report.OutputDir; it does not run scans.
type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	// AuthToken, if set, is required as a Bearer credential on every
	// dashboard API request except /healthz (internal/auth,
	// Milestone 20). Also settable via the BANNIN_AUTH_TOKEN env var
	// (Viper binds it below) so it never has to live in bannin.yaml.
	// Empty disables auth — fine on 127.0.0.1, risky on anything else.
	AuthToken string `mapstructure:"auth_token"`
	// WebDir is a directory of built dashboard assets (the output of
	// `npm run build`, i.e. web/dist) that `bannin serve` serves
	// alongside the API on the same origin, so the whole tool is one
	// process on one port with no separate dev server. Empty means
	// serve auto-detects ./web/dist and, failing that, serves the API
	// only.
	WebDir string `mapstructure:"web_dir"`
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

var validZapModes = map[string]bool{
	"quick": true, "full": true,
}

var validZapAuthMethods = map[string]bool{
	"form": true, "json": true, "header": true, "browser": true,
}

// Load reads BANNIN configuration from the given YAML file path, layered
// over built-in defaults. If path is empty, Load looks for ./bannin.yaml
// and falls back to defaults alone when no such file exists.
func Load(path string) (*Config, error) {
	v := viper.New()
	setDefaults(v)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("bannin")
	if err := v.BindEnv("server.auth_token", "BANNIN_AUTH_TOKEN"); err != nil {
		return nil, fmt.Errorf("config: binding BANNIN_AUTH_TOKEN: %w", err)
	}
	// ZAP auth credentials are secrets — bind env vars so they never have
	// to live in bannin.yaml.
	for key, env := range map[string]string{
		"zap.auth.password": "BANNIN_ZAP_AUTH_PASSWORD",
		"zap.auth.token":    "BANNIN_ZAP_AUTH_TOKEN",
		"zap.auth.username": "BANNIN_ZAP_AUTH_USERNAME",
	} {
		if err := v.BindEnv(key, env); err != nil {
			return nil, fmt.Errorf("config: binding %s: %w", env, err)
		}
	}

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
	v.SetDefault("report.formats", []string{"html", "json"})
	v.SetDefault("report.output_dir", "./bannin-report")
	v.SetDefault("policy.fail_on_severity", "high")
	v.SetDefault("storage.driver", "sqlite")
	v.SetDefault("storage.dsn", "./bannin.db")
	v.SetDefault("server.host", "127.0.0.1")
	v.SetDefault("server.port", 8080)
	v.SetDefault("logging.level", "info")
	v.SetDefault("zap.mode", "quick")
	v.SetDefault("zap.browser", "chrome-headless")
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
	if c.Server.Port < 0 || c.Server.Port > 65535 {
		return fmt.Errorf("config: server.port %d must be between 0 and 65535", c.Server.Port)
	}
	if c.Zap.Mode != "" && !validZapModes[c.Zap.Mode] {
		return fmt.Errorf("config: zap.mode %q must be one of quick, full", c.Zap.Mode)
	}
	if err := c.Zap.Auth.validate(); err != nil {
		return err
	}
	return nil
}

// validate checks the ZAP auth block is internally consistent: a known
// method, and the fields that method actually needs. Empty method means
// no authentication (unauthenticated scan), which is always valid.
func (a ZapAuthConfig) validate() error {
	if a.Method == "" {
		return nil
	}
	if !validZapAuthMethods[a.Method] {
		return fmt.Errorf("config: zap.auth.method %q must be one of form, json, header, browser", a.Method)
	}
	switch a.Method {
	case "header":
		if a.Token == "" {
			return fmt.Errorf("config: zap.auth.method %q requires zap.auth.token (or BANNIN_ZAP_AUTH_TOKEN)", a.Method)
		}
	default: // form, json, browser
		if a.LoginURL == "" {
			return fmt.Errorf("config: zap.auth.method %q requires zap.auth.login_url", a.Method)
		}
		if a.Username == "" || a.Password == "" {
			return fmt.Errorf("config: zap.auth.method %q requires zap.auth.username and zap.auth.password (password via BANNIN_ZAP_AUTH_PASSWORD)", a.Method)
		}
	}
	return nil
}
