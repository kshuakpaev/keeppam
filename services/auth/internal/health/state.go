package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

// State is shared by API and SSH-worker for /livez /readyz and SIGTERM drain.
type State struct {
	draining atomic.Bool
	check    atomic.Value // func(context.Context) error
}

func New() *State {
	return &State{}
}

func (s *State) SetDraining(v bool) {
	if s == nil {
		return
	}
	s.draining.Store(v)
}

func (s *State) Draining() bool {
	return s != nil && s.draining.Load()
}

func (s *State) SetCheck(fn func(context.Context) error) {
	if s == nil {
		return
	}
	s.check.Store(fn)
}

func (s *State) ServeLive(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *State) ServeReady(w http.ResponseWriter, r *http.Request) {
	if s.Draining() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "draining"})
		return
	}
	fn, _ := s.check.Load().(func(context.Context) error)
	if fn != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := fn(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *State) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", s.ServeLive)
	mux.HandleFunc("/healthz", s.ServeLive)
	mux.HandleFunc("/readyz", s.ServeReady)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
