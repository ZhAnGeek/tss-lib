package log

import "context"

const (
	TSSLib string = "tss-lib-private"
)

var logger ILogger

func init() {
	logger = newDefaultLogger()
}

func SetLogger(mLogger ILogger) {
	logger = mLogger
}

func SetLogLevel(level Level) error {
	return logger.SetLogLevel(level)
}

func Debug(ctx context.Context, format string, args ...interface{}) {
	logger.Debug(ctx, format, args...)
}

func Info(ctx context.Context, format string, args ...interface{}) {
	logger.Info(ctx, format, args...)
}

func Warn(ctx context.Context, format string, args ...interface{}) {
	logger.Warn(ctx, format, args...)
}

func Error(ctx context.Context, format string, args ...interface{}) {
	logger.Error(ctx, format, args...)
}

func Fatal(ctx context.Context, format string, args ...interface{}) {
	logger.Fatal(ctx, format, args...)
}

func Sync(ctx context.Context) error {
	return logger.Sync(ctx)
}
