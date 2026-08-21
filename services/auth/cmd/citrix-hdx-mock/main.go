package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// citrix-hdx-mock: OEM HDX terminate stub for KeepPAM SOW phase 3.
// Does NOT decode real HDX — only exercises the plugin HTTP contract.

type sess struct {
	ID        string
	KeepPAM   string
	Started   time.Time
	VDAHost   string
	Listen    string
	Username  string
	Events    []map[string]any
}

var (
	mu   sync.Mutex
	store = map[string]*sess{}
)

func main() {
	addr := env("ADDR", ":14950")
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"status": "ok", "vendor": "keeppam-mock", "version": "0.1",
			"capabilities": []string{"terminate", "record_meta"},
		})
	})
	mux.HandleFunc("/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", 405)
			return
		}
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		id := "mock-" + randHex(8)
		listen := env("LISTEN_ADDR", "127.0.0.1:14940")
		s := &sess{
			ID: id, KeepPAM: str(in["keeppam_session_id"]),
			Started: time.Now().UTC(), VDAHost: str(in["vda_host"]),
			Listen: listen, Username: str(in["username"]),
			Events: []map[string]any{
				{"t": time.Now().UTC().Format(time.RFC3339Nano), "event": "hdx_started", "meta": map[string]any{
					"vda": str(in["vda_host"]), "mode": "terminate", "mock": true,
				}},
				{"t": time.Now().UTC().Format(time.RFC3339Nano), "event": "hdx_meta", "meta": map[string]any{
					"note": "no real HDX frames — OEM binary required",
				}},
			},
		}
		mu.Lock()
		store[id] = s
		mu.Unlock()
		log.Printf("start %s keeppam=%s vda=%s", id, s.KeepPAM, s.VDAHost)
		writeJSON(w, map[string]any{
			"plugin_session_id": id, "status": "active", "mode": "terminate",
			"listen_addr": listen, "message": "mock terminate — replace with OEM plugin",
		})
	})
	mux.HandleFunc("/v1/sessions/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/sessions/")
		if id == "" || id == r.URL.Path {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		s := store[id]
		mu.Unlock()
		if s == nil {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodDelete {
			mu.Lock()
			delete(store, id)
			mu.Unlock()
			log.Printf("stop %s", id)
			w.WriteHeader(204)
			return
		}
		writeJSON(w, map[string]any{
			"plugin_session_id": id, "status": "active", "events": s.Events,
		})
	})
	log.Printf("citrix-hdx-mock listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
