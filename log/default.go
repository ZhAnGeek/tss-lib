// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package log

import (
	"context"
	"fmt"
	"sync"
	"time"

	_const "github.com/Safulet/tss-lib-private/v2/const"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var mpcLogTag = zap.String("library", _const.TSSLib)

type defaultLogger struct {
	zapLogger *zap.Logger
	rwLock    sync.RWMutex
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
	zapLogger, err := zapConfig.Build(zap.AddCallerSkip(2))
	return zapLogger, err
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
	d.rwLock.Lock()
	defer d.rwLock.Unlock()
	d.zapLogger = zapLogger
	return nil
}

func (d *defaultLogger) Debug(ctx context.Context, msg string, any ...interface{}) {
	d.rwLock.RLock()
	defer d.rwLock.RUnlock()
	d.zapLogger.Debug(fmt.Sprintf(msg, any...), mpcLogTag)
}

func (d *defaultLogger) Info(ctx context.Context, msg string, any ...interface{}) {
	d.rwLock.RLock()
	defer d.rwLock.RUnlock()
	d.zapLogger.Info(fmt.Sprintf(msg, any...), mpcLogTag)
}

func (d *defaultLogger) Warn(ctx context.Context, msg string, any ...interface{}) {
	d.rwLock.RLock()
	defer d.rwLock.RUnlock()
	d.zapLogger.Warn(fmt.Sprintf(msg, any...), mpcLogTag)
}

func (d *defaultLogger) Error(ctx context.Context, msg string, any ...interface{}) {
	d.rwLock.RLock()
	defer d.rwLock.RUnlock()
	d.zapLogger.Error(fmt.Sprintf(msg, any...), mpcLogTag)
}

func (d *defaultLogger) Fatal(ctx context.Context, msg string, any ...interface{}) {
	d.rwLock.RLock()
	defer d.rwLock.RUnlock()
	d.zapLogger.Fatal(fmt.Sprintf(msg, any...), mpcLogTag)
}

func (d *defaultLogger) Sync(ctx context.Context) error {
	d.rwLock.RLock()
	defer d.rwLock.RUnlock()
	return d.zapLogger.Sync()
}
