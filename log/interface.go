// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package log

import "context"

// Level log level
type Level int

const (
	// FatalLevel error log level
	FatalLevel Level = iota + 1
	// ErrorLevel error log level
	ErrorLevel
	// WarnLevel warn log level
	WarnLevel
	// InfoLevel info log level
	InfoLevel
	// DebugLevel debug log level
	DebugLevel
)

type ILogger interface {
	SetLogLevel(level Level) error
	Debug(context.Context, string, ...interface{})
	Info(context.Context, string, ...interface{})
	Warn(context.Context, string, ...interface{})
	Error(context.Context, string, ...interface{})
	Fatal(context.Context, string, ...interface{})
	Sync(ctx context.Context) error
}
