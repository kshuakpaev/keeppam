package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPostJSONOK(t *testing.T) {
	var gotAuth, gotUA, gotCT string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		gotCT = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	err := PostJSON(context.Background(), srv.URL, "Bearer abc", 2*time.Second, map[string]any{
		"source": "keeppam", "event": "jit.created",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer abc" || gotUA != "KeepPAM-Notify/1.0" || gotCT != "application/json" {
		t.Fatalf("headers auth=%s ua=%s ct=%s", gotAuth, gotUA, gotCT)
	}
	if body["event"] != "jit.created" {
		t.Fatalf("body %+v", body)
	}
}

func TestPostJSONHeaderSplit(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Hook-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := PostJSON(context.Background(), srv.URL, "X-Hook-Token: secret-value", time.Second, map[string]any{"ok": true}); err != nil {
		t.Fatal(err)
	}
	if got != "secret-value" {
		t.Fatalf("header %q", got)
	}
}

func TestPostJSONStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	err := PostJSON(context.Background(), srv.URL, "", time.Second, map[string]any{"e": 1})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err=%v", err)
	}
}

func TestPostJSONEmptyURL(t *testing.T) {
	if err := PostJSON(context.Background(), "  ", "", time.Second, map[string]any{}); err == nil {
		t.Fatal("expected error")
	}
}
