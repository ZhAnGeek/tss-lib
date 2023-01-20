package log

import "context"

// LogLevel log level
type Level int

const (
	// Fatal error log level
	FatalLevel Level = iota + 1
	// Error error log level
	ErrorLevel
	// Warn warn log level
	WarnLevel
	// Info info log level
	InfoLevel
	// Debug debug log level
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
