package logging

import (
	"bytes"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestNewDefaultLevelFiltersDebug(t *testing.T) {
	buf := &bytes.Buffer{}
	logger, err := New("", zapcore.AddSync(buf))
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	logger.Debug("should not appear")
	logger.Info("should appear")
	logger.Sync()

	out := buf.String()
	if strings.Contains(out, "should not appear") {
		t.Errorf("debug message logged at default info level: %q", out)
	}
	if !strings.Contains(out, "should appear") {
		t.Errorf("info message missing from output: %q", out)
	}
}

func TestNewDebugLevelIncludesDebug(t *testing.T) {
	buf := &bytes.Buffer{}
	logger, err := New("debug", zapcore.AddSync(buf))
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	logger.Debug("debug message")
	logger.Sync()

	if !strings.Contains(buf.String(), "debug message") {
		t.Errorf("debug message missing at debug level: %q", buf.String())
	}
}

func TestNewWithFields(t *testing.T) {
	buf := &bytes.Buffer{}
	logger, err := New("info", zapcore.AddSync(buf))
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	logger.Info("scan starting", zap.String("target", "."))
	logger.Sync()

	out := buf.String()
	if !strings.Contains(out, "target") || !strings.Contains(out, ".") {
		t.Errorf("output missing logged field: %q", out)
	}
}

func TestNewInvalidLevel(t *testing.T) {
	if _, err := New("verbose", nil); err == nil {
		t.Fatal("New should reject an unrecognized level")
	}
}

func TestNewDefaultsToStderr(t *testing.T) {
	logger, err := New("info", nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	logger.Info("smoke test")
	logger.Sync()
}
