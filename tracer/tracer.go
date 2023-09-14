package tracer

import (
	"context"
	"regexp"
	"runtime"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	_const "github.com/Safulet/tss-lib-private/const"
)

var reFuncRemove = regexp.MustCompile(`[*()]`)

func GetTracer() trace.Tracer {
	return otel.GetTracerProvider().Tracer(_const.TSSLib)
}

func Start(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return GetTracer().Start(ctx, spanName, opts...)
}

func getCallerName() string {
	pc, _, _, ok := runtime.Caller(2)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		name := details.Name()
		// remove all *,(,) in name by regexp
		name = reFuncRemove.ReplaceAllString(name, "")
		return name
	}
	return ""
}

func StartWithFuncSpan(ctx context.Context, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	spanName := getCallerName()
	return Start(ctx, spanName, opts...)
}

func Extract(ctx context.Context) map[string]string {
	if ctx == nil {
		return nil
	}
	propagator := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
	carrier := propagation.MapCarrier{}
	propagator.Inject(ctx, carrier)
	return carrier
}

func Inject(ctx context.Context, carrier map[string]string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(carrier) == 0 {
		return ctx
	}
	propagator := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
	return propagator.Extract(ctx, propagation.MapCarrier(carrier))
}
