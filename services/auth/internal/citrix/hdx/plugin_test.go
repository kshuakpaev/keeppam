package hdx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientStartStop(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Health{Status: "ok", Capabilities: []string{"terminate"}, Vendor: "mock"})
	})
	mux.HandleFunc("/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		_ = json.NewEncoder(w).Encode(StartResponse{
			PluginSessionID: "plg-1", Status: "active", Mode: "terminate", ListenAddr: "127.0.0.1:14940",
		})
	})
	mux.HandleFunc("/v1/sessions/plg-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(204)
			return
		}
		_ = json.NewEncoder(w).Encode(StatusResponse{PluginSessionID: "plg-1", Status: "active"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx := context.Background()
	c := NewClient(srv.URL)
	c.HTTP = srv.Client()
	h, err := c.Health(ctx)
	if err != nil || h.Status != "ok" {
		t.Fatalf("%v %#v", err, h)
	}
	st, err := c.Start(ctx, StartRequest{KeepPAMSessionID: "s1", VDAHost: "vda", Username: "u", Password: "p"})
	if err != nil || st.PluginSessionID != "plg-1" {
		t.Fatalf("%v %#v", err, st)
	}
	if err := c.Stop(ctx, st.PluginSessionID); err != nil {
		t.Fatal(err)
	}
}
