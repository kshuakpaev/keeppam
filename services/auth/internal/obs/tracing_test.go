package obs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestNormalizeOTLPEndpoint(t *testing.T) {
	if NormalizeOTLPEndpoint("http://tempo:4318/v1/traces") != "tempo:4318" {
		t.Fatal(NormalizeOTLPEndpoint("http://tempo:4318/v1/traces"))
	}
	if NormalizeOTLPEndpoint("http://jaeger:4318/v1/traces") != "jaeger:4318" {
		t.Fatal(NormalizeOTLPEndpoint("http://jaeger:4318/v1/traces"))
	}
	if NormalizeOTLPEndpoint("") != "" {
		t.Fatal("empty")
	}
}

func TestOTELVia(t *testing.T) {
	if OTELVia("") != "off" {
		t.Fatal(OTELVia(""))
	}
	if OTELVia("http://otel-collector:4318") != "collector" {
		t.Fatal(OTELVia("http://otel-collector:4318"))
	}
	if OTELVia("http://tempo:4318/v1/traces") != "tempo" {
		t.Fatal(OTELVia("http://tempo:4318/v1/traces"))
	}
	if OTELVia("http://jaeger:4318") != "jaeger" {
		t.Fatal(OTELVia("http://jaeger:4318"))
	}
}

func TestStartSessionSpan(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	otel.SetTracerProvider(tp)
	tracingOn.Store(true)
	t.Cleanup(func() {
		tracingOn.Store(false)
		otel.SetTracerProvider(noop.NewTracerProvider())
	})
	ctx, end := StartSessionSpan(context.Background(), "ssh", "sid-1", "web-1")
	end()
	_ = ctx
	spans := sr.Ended()
	if len(spans) != 1 || spans[0].Name() != "ssh.session" {
		t.Fatalf("spans=%v", spans)
	}
}

func TestInitTracingDisabled(t *testing.T) {
	stop, err := InitTracing(context.Background(), "", "keeppam-api")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stop(context.Background()) }()
	if TracingEnabled() {
		t.Fatal("expected disabled")
	}
}

func TestHTTPTracingSpan(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	otel.SetTracerProvider(tp)
	tracingOn.Store(true)
	t.Cleanup(func() {
		tracingOn.Store(false)
		otel.SetTracerProvider(noop.NewTracerProvider())
	})

	r := chi.NewRouter()
	r.Use(HTTPTracing)
	r.Get("/api/v1/auth/me", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("spans=%d", len(spans))
	}
	if spans[0].Name() != "GET /api/v1/auth/me" {
		t.Fatalf("name=%s", spans[0].Name())
	}
}

func TestHTTPTracingSkipsHealthz(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	otel.SetTracerProvider(tp)
	tracingOn.Store(true)
	t.Cleanup(func() {
		tracingOn.Store(false)
		otel.SetTracerProvider(noop.NewTracerProvider())
	})
	h := HTTPTracing(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if len(sr.Ended()) != 0 {
		t.Fatal("healthz should not span")
	}
}
