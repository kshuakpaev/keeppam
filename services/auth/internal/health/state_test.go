package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLivezOK(t *testing.T) {
	s := New()
	rec := httptest.NewRecorder()
	s.ServeLive(rec, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestReadyzDraining(t *testing.T) {
	s := New()
	s.SetDraining(true)
	rec := httptest.NewRecorder()
	s.ServeReady(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "draining" {
		t.Fatalf("body %v", body)
	}
}

func TestReadyzCheck(t *testing.T) {
	s := New()
	s.SetCheck(func(context.Context) error { return errors.New("pg down") })
	rec := httptest.NewRecorder()
	s.ServeReady(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", rec.Code)
	}
	s.SetCheck(func(context.Context) error { return nil })
	rec = httptest.NewRecorder()
	s.ServeReady(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
}
