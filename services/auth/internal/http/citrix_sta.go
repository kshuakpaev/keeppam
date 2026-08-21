package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/keeppam/auth/internal/citrix"
)

// KeepPAM STA stub validation (SOW-CITRIX-HDX slice 1).
// Real CtxSta.dll CGI is not fully emulated; clients/ops can probe tickets here.
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
		"via":        "keeppam-sta-stub",
	})
}
