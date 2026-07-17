package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") returned error with no config file present: %v", err)
	}

	if cfg.Scan.Target != "." {
		t.Errorf("Scan.Target = %q, want %q", cfg.Scan.Target, ".")
	}
	if cfg.Policy.FailOnSeverity != "high" {
		t.Errorf("Policy.FailOnSeverity = %q, want %q", cfg.Policy.FailOnSeverity, "high")
	}
	if cfg.Storage.Driver != "sqlite" {
		t.Errorf("Storage.Driver = %q, want %q", cfg.Storage.Driver, "sqlite")
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bannin.yaml")
	contents := `
scan:
  target: "./src"
  plugins: ["semgrep"]
policy:
  fail_on_severity: "critical"
`
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q) returned error: %v", path, err)
	}

	if cfg.Scan.Target != "./src" {
		t.Errorf("Scan.Target = %q, want %q", cfg.Scan.Target, "./src")
	}
	if len(cfg.Scan.Plugins) != 1 || cfg.Scan.Plugins[0] != "semgrep" {
		t.Errorf("Scan.Plugins = %v, want [semgrep]", cfg.Scan.Plugins)
	}
	if cfg.Policy.FailOnSeverity != "critical" {
		t.Errorf("Policy.FailOnSeverity = %q, want %q", cfg.Policy.FailOnSeverity, "critical")
	}
	// Untouched sections should still carry defaults.
	if cfg.Storage.Driver != "sqlite" {
		t.Errorf("Storage.Driver = %q, want default %q", cfg.Storage.Driver, "sqlite")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("Load with an explicit missing path should return an error")
	}
}

func TestValidateRejectsUnknownSeverity(t *testing.T) {
	cfg := &Config{Policy: PolicyConfig{FailOnSeverity: "extreme"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject an unknown fail_on_severity")
	}
}

func TestValidateRejectsUnknownStorageDriver(t *testing.T) {
	cfg := &Config{Storage: StorageConfig{Driver: "mongodb"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject an unknown storage driver")
	}
}

func TestValidateRejectsUnknownLogLevel(t *testing.T) {
	cfg := &Config{Logging: LoggingConfig{Level: "verbose"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject an unknown logging level")
	}
}

func TestValidateRejectsUnknownZapMode(t *testing.T) {
	cfg := &Config{Zap: ZapConfig{Mode: "aggressive"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject an unknown zap.mode")
	}
}

func TestValidateAcceptsKnownZapModes(t *testing.T) {
	for _, m := range []string{"", "quick", "full"} {
		cfg := &Config{Zap: ZapConfig{Mode: m}}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate rejected valid zap.mode %q: %v", m, err)
		}
	}
}

func TestValidateZapAuth(t *testing.T) {
	cases := []struct {
		name string
		auth ZapAuthConfig
		ok   bool
	}{
		{"empty method ok", ZapAuthConfig{}, true},
		{"unknown method", ZapAuthConfig{Method: "kerberos"}, false},
		{"form complete", ZapAuthConfig{Method: "form", LoginURL: "http://x/login", Username: "u", Password: "p"}, true},
		{"form missing url", ZapAuthConfig{Method: "form", Username: "u", Password: "p"}, false},
		{"form missing creds", ZapAuthConfig{Method: "form", LoginURL: "http://x/login"}, false},
		{"json complete", ZapAuthConfig{Method: "json", LoginURL: "http://x/api/login", Username: "u", Password: "p"}, true},
		{"browser complete", ZapAuthConfig{Method: "browser", LoginURL: "http://x/login", Username: "u", Password: "p"}, true},
		{"header with token", ZapAuthConfig{Method: "header", Token: "Bearer x"}, true},
		{"header missing token", ZapAuthConfig{Method: "header"}, false},
	}
	for _, c := range cases {
		err := (&Config{Zap: ZapConfig{Auth: c.auth}}).Validate()
		if c.ok && err != nil {
			t.Errorf("%s: unexpected error: %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: expected validation error, got none", c.name)
		}
	}
}
