package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/keeppam/auth/internal/eidas"
)

func (s *Server) handleGetEIDASSettings(w http.ResponseWriter, r *http.Request) {
	if s.eidas == nil {
		writeErr(w, http.StatusServiceUnavailable, "eidas unavailable")
		return
	}
	cfg, err := s.eidas.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handlePutEIDASSettings(w http.ResponseWriter, r *http.Request) {
	if s.eidas == nil {
		writeErr(w, http.StatusServiceUnavailable, "eidas unavailable")
		return
	}
	sess := mustSess(r)
	var in eidas.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := s.eidas.Put(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleEIDASTest(w http.ResponseWriter, r *http.Request) {
	if s.eidas == nil {
		writeErr(w, http.StatusServiceUnavailable, "eidas unavailable")
		return
	}
	resp, err := s.eidas.Test(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": resp})
}
