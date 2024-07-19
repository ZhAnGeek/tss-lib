// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package log

import "context"

const (
	// Fatal error log level
	FatalLevel = "fatal"
	// Error error log level
	ErrorLevel = "error"
	// Warn warn log level
	WarnLevel = "warn"
	// Info info log level
	InfoLevel = "info"
	// Debug debug log level
	DebugLevel = "debug"
)

type ILogger interface {
	SetLogLevel(level string) error
	Debug(context.Context, string, ...interface{})
	Info(context.Context, string, ...interface{})
	Warn(context.Context, string, ...interface{})
	Error(context.Context, string, ...interface{})
	Fatal(context.Context, string, ...interface{})
	Sync(ctx context.Context) error
}
