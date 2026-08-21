package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/citrix"
)

// JSON validate (phase 1) + CtxSta.dll CGI (phase 2).
func (s *Server) handleCitrixSTAValidate(w http.ResponseWriter, r *http.Request) {
	ticket := chi.URLParam(r, "ticket")
	if ticket == "" {
		ticket = r.URL.Query().Get("ticket")
	}
	sid, aid, err := citrix.ValidateSTATicket(r.Context(), s.sessions.Redis(), ticket)
	if err != nil {
		writeErr(w, http.StatusNotFound, "ticket invalid or expired")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"session_id": sid.String(),
		"asset_id":   aid.String(),
		"via":        "keeppam-sta",
	})
}

// CtxSta.dll-compatible STA endpoint (text/plain). Used by Workspace when KeepPAM is configured as STA.
func (s *Server) handleCitrixCtxSta(w http.ResponseWriter, r *http.Request) {
	ticket := r.URL.Query().Get("ticket")
	if ticket == "" {
		ticket = chi.URLParam(r, "ticket")
	}
	sid, _, err := citrix.ValidateSTATicket(r.Context(), s.sessions.Redis(), ticket)
	if err != nil {
		http.Error(w, "", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(citrix.CtxStaSuccessBody(ticket, sid.String())))
}

// Probe asset-configured external STA URLs with a ticket (admin diagnostic).
func (s *Server) handleCitrixSTAProbe(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var body struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Ticket) == "" {
		writeErr(w, http.StatusBadRequest, "ticket required")
		return
	}
	a, err := s.assets.Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "asset not found")
		return
	}
	if a.Protocol != "citrix" {
		writeErr(w, http.StatusBadRequest, "not a citrix asset")
		return
	}
	ok, which, resp, err := citrix.ProbeSTAURLs(r.Context(), nil, a.CitrixSTAURLs, body.Ticket)
	if err != nil && !ok {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": ok, "sta_url": which, "body_preview": truncateCitrix(resp, 500),
	})
}

func truncateCitrix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
