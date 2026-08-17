package obs

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/go-chi/chi/v5"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
	"go.opentelemetry.io/otel/trace"
)

var tracingOn atomic.Bool

func TracingEnabled() bool {
	return tracingOn.Load()
}

func Tracer() trace.Tracer {
	return otel.Tracer("keeppam")
}

func InitTracing(ctx context.Context, endpoint, service string) (func(context.Context) error, error) {
	endpoint = NormalizeOTLPEndpoint(endpoint)
	if endpoint == "" {
		tracingOn.Store(false)
		return func(context.Context) error { return nil }, nil
	}
	if service == "" {
		service = "keeppam-api"
	}
	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}
	attrs := []attribute.KeyValue{
		semconv.ServiceName(service),
		semconv.ServiceNamespace("keeppam"),
	}
	if env := strings.TrimSpace(os.Getenv("KEEPPAM_OTEL_ENV")); env != "" {
		attrs = append(attrs, attribute.String("deployment.environment", env))
	}
	res, err := resource.New(ctx, resource.WithAttributes(attrs...))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(1))),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	tracingOn.Store(true)
	return tp.Shutdown, nil
}

func NormalizeOTLPEndpoint(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, "/v1/traces")
	return strings.TrimSpace(s)
}

// OTELVia classifies the OTLP endpoint: collector | tempo | jaeger | otlp | off.
func OTELVia(raw string) string {
	e := strings.ToLower(NormalizeOTLPEndpoint(raw))
	if e == "" {
		return "off"
	}
	if strings.Contains(e, "otel-collector") || strings.Contains(e, "otelcol") {
		return "collector"
	}
	if strings.Contains(e, "tempo") {
		return "tempo"
	}
	if strings.Contains(e, "jaeger") {
		return "jaeger"
	}
	return "otlp"
}

// StartSessionSpan records a PAM session (SSH worker / API). No secrets in attributes.
func StartSessionSpan(ctx context.Context, protocol, sessionID, asset string) (context.Context, func()) {
	if !TracingEnabled() {
		return ctx, func() {}
	}
	if protocol == "" {
		protocol = "session"
	}
	ctx, span := Tracer().Start(ctx, protocol+".session",
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("session.id", sessionID),
			attribute.String("session.protocol", protocol),
			attribute.String("keeppam.asset", asset),
		),
	)
	return ctx, func() { span.End() }
}

func HTTPTracing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !TracingEnabled() || r.URL.Path == "/metrics" || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			next.ServeHTTP(w, r)
			return
		}
		ctx, span := Tracer().Start(r.Context(), r.Method+" "+r.URL.Path,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("url.path", r.URL.Path),
			),
		)
		defer span.End()
		ww := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		req := r.WithContext(ctx)
		next.ServeHTTP(ww, req)
		route := req.URL.Path
		if rc := chi.RouteContext(req.Context()); rc != nil {
			if p := rc.RoutePattern(); p != "" {
				route = p
				span.SetName(req.Method + " " + route)
			}
		}
		span.SetAttributes(
			attribute.String("http.route", route),
			attribute.Int("http.response.status_code", ww.code),
		)
		if ww.code >= 500 {
			span.SetStatus(codes.Error, http.StatusText(ww.code))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
