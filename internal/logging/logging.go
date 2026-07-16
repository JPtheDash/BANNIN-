package logging

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New builds a structured logger at the given level (one of debug, info,
// warn, error — as validated by internal/config; empty defaults to info),
// writing console-formatted output to out. If out is nil, it defaults to
// os.Stderr.
func New(level string, out zapcore.WriteSyncer) (*zap.Logger, error) {
	zapLevel, err := parseLevel(level)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = zapcore.AddSync(os.Stderr)
	}

	encoderCfg := zap.NewDevelopmentEncoderConfig()
	encoderCfg.TimeKey = "ts"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	core := zapcore.NewCore(zapcore.NewConsoleEncoder(encoderCfg), out, zapLevel)
	return zap.New(core), nil
}

func parseLevel(level string) (zapcore.Level, error) {
	if level == "" {
		return zapcore.InfoLevel, nil
	}
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		return 0, fmt.Errorf("logging: invalid level %q: %w", level, err)
	}
	return zapLevel, nil
}
