package main

import (
	"bytes"
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

// citrix-hdx-mock: OEM HDX terminate + recording stub (SOW phases 3–4).
// Does NOT decode real HDX — exercises plugin HTTP + ingest callback.

type sess struct {
	ID       string
	KeepPAM  string
	Started  time.Time
	VDAHost  string
	Listen   string
	Username string
	Token    string
	Callback string
	Events   []map[string]any
	seq      int
}

var (
	mu    sync.Mutex
	store = map[string]*sess{}
)

func main() {
	addr := env("ADDR", ":14950")
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"status": "ok", "vendor": "keeppam-mock", "version": "0.2",
			"capabilities": []string{"terminate", "record", "ocr", "record_meta"},
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
		now := time.Now().UTC()
		s := &sess{
			ID: id, KeepPAM: str(in["keeppam_session_id"]),
			Started: now, VDAHost: str(in["vda_host"]),
			Listen: listen, Username: str(in["username"]),
			Token: str(in["ingest_token"]), Callback: str(in["callback_url"]),
		}
		s.push(1, "hdx_started", map[string]any{"vda": s.VDAHost, "mode": "terminate", "mock": true})
		s.push(2, "hdx_frame", map[string]any{"w": 1280, "h": 720, "offset": 0.5, "note": "meta only — no pixels in mock"})
		s.push(3, "hdx_ocr", map[string]any{"text": "KeepPAM mock desktop", "offset": 0.6})
		s.push(4, "hdx_keystroke", map[string]any{"line": "whoami", "offset": 1.2})
		s.push(5, "hdx_ocr", map[string]any{"text": "C:\\Users\\ops>", "offset": 1.5})
		mu.Lock()
		store[id] = s
		mu.Unlock()
		log.Printf("start %s keeppam=%s vda=%s callback=%v", id, s.KeepPAM, s.VDAHost, s.Callback != "")
		writeJSON(w, map[string]any{
			"plugin_session_id": id, "status": "active", "mode": "terminate",
			"listen_addr": listen, "message": "mock terminate+record — replace with OEM plugin",
		})
		if s.Callback != "" && s.Token != "" {
			go postIngest(s)
		}
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
			s.push(s.seq+1, "hdx_ended", map[string]any{"reason": "stop"})
			if s.Callback != "" && s.Token != "" {
				postIngest(s)
			}
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

func (s *sess) push(seq int, event string, meta map[string]any) {
	if seq > s.seq {
		s.seq = seq
	}
	s.Events = append(s.Events, map[string]any{
		"t": time.Now().UTC().Format(time.RFC3339Nano), "event": event, "seq": seq, "meta": meta,
	})
}

func postIngest(s *sess) {
	mu.Lock()
	events := append([]map[string]any{}, s.Events...)
	cb, tok := s.Callback, s.Token
	mu.Unlock()
	body, _ := json.Marshal(map[string]any{"events": events})
	req, err := http.NewRequest(http.MethodPost, cb, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("ingest callback: %v", err)
		return
	}
	res.Body.Close()
	log.Printf("ingest callback status=%d events=%d", res.StatusCode, len(events))
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
