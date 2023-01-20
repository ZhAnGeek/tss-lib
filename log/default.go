package log

import (
	"context"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"time"
)

var mpcLogTag = zap.String("library", SDK)

type defaultLogger struct {
	zapLogger *zap.Logger
}

func initZap(logLevel zapcore.Level) (*zap.Logger, error) {
	encoderConfig := zapcore.EncoderConfig{
		// Keys can be anything except the empty string.
		TimeKey:       "time",
		LevelKey:      "level",
		NameKey:       "name",
		CallerKey:     "line",
		FunctionKey:   zapcore.OmitKey,
		MessageKey:    "message",
		StacktraceKey: "trace",
		LineEnding:    zapcore.DefaultLineEnding,
		EncodeLevel:   zapcore.CapitalLevelEncoder,
		EncodeTime: func(time time.Time, encoder zapcore.PrimitiveArrayEncoder) {
			encoder.AppendString(time.Format("2006-01-02 15:04:05.999 -0700"))
		},
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	zapConfig := zap.Config{
		Level:            zap.NewAtomicLevelAt(logLevel),
		Encoding:         "console",
		EncoderConfig:    encoderConfig,
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stdout"},
	}
	logger, err := zapConfig.Build(zap.AddCallerSkip(2))
	return logger, err
}

func newDefaultLogger() *defaultLogger {
	zapLogger, err := initZap(zapcore.DebugLevel)
	if err != nil {
		panic(err)
	}
	return &defaultLogger{zapLogger: zapLogger}
}

func (d *defaultLogger) SetLogLevel(level Level) error {
	zapLevel := zapcore.DebugLevel
	switch level {
	case DebugLevel:
		zapLevel = zapcore.DebugLevel
	case InfoLevel:
		zapLevel = zapcore.InfoLevel
	case WarnLevel:
		zapLevel = zapcore.WarnLevel
	case ErrorLevel:
		zapLevel = zapcore.ErrorLevel
	case FatalLevel:
		zapLevel = zapcore.FatalLevel
	}
	zapLogger, err := initZap(zapLevel)
	if err != nil {
		return err
	}
	d.zapLogger = zapLogger
	return nil
}

func (d *defaultLogger) Debug(ctx context.Context, msg string, any ...interface{}) {
	d.zapLogger.Debug(fmt.Sprintf(msg, any...), mpcLogTag)
}

func (d *defaultLogger) Info(ctx context.Context, msg string, any ...interface{}) {
	d.zapLogger.Info(fmt.Sprintf(msg, any...), mpcLogTag)
}

func (d *defaultLogger) Warn(ctx context.Context, msg string, any ...interface{}) {
	d.zapLogger.Warn(fmt.Sprintf(msg, any...), mpcLogTag)
}

func (d *defaultLogger) Error(ctx context.Context, msg string, any ...interface{}) {
	d.zapLogger.Error(fmt.Sprintf(msg, any...), mpcLogTag)
}

func (d *defaultLogger) Fatal(ctx context.Context, msg string, any ...interface{}) {
	d.zapLogger.Fatal(fmt.Sprintf(msg, any...), mpcLogTag)
}

func (d *defaultLogger) Sync(ctx context.Context) error {
	return d.zapLogger.Sync()
}
