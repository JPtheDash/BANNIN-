package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStderr redirects os.Stderr for the duration of fn and returns
// everything written to it. Needed because the scan command's logger
// writes straight to os.Stderr rather than through Cobra's output streams.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestVersionCmd(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("version command returned error: %v", err)
	}
	if got := buf.String(); !strings.Contains(got, "bannin") {
		t.Errorf("version output = %q, want it to contain %q", got, "bannin")
	}
}

// TestScanCmdRejectsUnknownPlugin proves the full wiring — config load,
// logging, and internal/scanner resolution against the real
// DefaultRegistry — without executing any actual scanner tool (unit
// tests must not shell out to semgrep/trivy/etc., which may not be
// installed). A config naming a nonexistent plugin exercises everything
// up to the point where real tools would run.
func TestScanCmdRejectsUnknownPlugin(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "bannin.yaml")
	cfg := "scan:\n  plugins: [\"semgrep\", \"no-such-plugin\"]\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"scan", "--config", cfgPath})

	var runErr error
	stderr := captureStderr(t, func() {
		runErr = rootCmd.Execute()
	})

	if runErr == nil {
		t.Fatal("scan should error when the config names an unregistered plugin")
	}
	if !strings.Contains(runErr.Error(), "no-such-plugin") {
		t.Errorf("scan error = %q, want it to name the unknown plugin", runErr.Error())
	}
	// The registered plugin names appear in the error's "(registered:
	// ...)" suffix — all four concrete plugins should be wired in.
	for _, name := range []string{"gitleaks", "osv", "semgrep", "trivy"} {
		if !strings.Contains(runErr.Error(), name) {
			t.Errorf("scan error = %q, want registered plugin %q listed", runErr.Error(), name)
		}
	}
	if !strings.Contains(stderr, "target") {
		t.Errorf("scan log output = %q, want it to contain the loaded config target", stderr)
	}
}
