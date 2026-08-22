package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// geo-witness-mock: HTTP witness for SOW-GEO-HA phase 4 (single primary lease).

var (
	mu      sync.Mutex
	holder  string
	expires time.Time
)

func main() {
	addr := env("ADDR", ":14960")
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"status": "ok", "vendor": "keeppam-mock"})
	})
	mux.HandleFunc("/v1/lease", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			h, ok := holder, time.Now().Before(expires)
			mu.Unlock()
			if !ok || h == "" {
				writeJSON(w, map[string]any{"holder_site_id": "", "status": "free"})
				return
			}
			writeJSON(w, map[string]any{"holder_site_id": h, "status": "held"})
		case http.MethodPost:
			var in map[string]any
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				http.Error(w, "bad json", 400)
				return
			}
			sid := strings.TrimSpace(str(in["site_id"]))
			ttl := 30
			if n, ok := in["ttl_seconds"].(float64); ok && n > 0 {
				ttl = int(n)
			}
			mu.Lock()
			defer mu.Unlock()
			now := time.Now().UTC()
			if holder != "" && now.Before(expires) && holder != sid {
				w.WriteHeader(http.StatusConflict)
				writeJSON(w, map[string]any{"holder_site_id": holder, "status": "held_by_other"})
				return
			}
			holder = sid
			expires = now.Add(time.Duration(ttl) * time.Second)
			writeJSON(w, map[string]any{"holder_site_id": holder, "status": "acquired", "ttl_seconds": ttl})
		case http.MethodDelete:
			mu.Lock()
			holder = ""
			expires = time.Time{}
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method", 405)
		}
	})
	log.Printf("geo-witness-mock on %s", addr)
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
