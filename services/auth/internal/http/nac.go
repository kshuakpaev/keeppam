package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/keeppam/auth/internal/nac"
)

func (s *Server) handleGetNACSettings(w http.ResponseWriter, r *http.Request) {
	if s.nac == nil {
		writeErr(w, http.StatusServiceUnavailable, "nac unavailable")
		return
	}
	cfg, err := s.nac.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handlePutNACSettings(w http.ResponseWriter, r *http.Request) {
	if s.nac == nil {
		writeErr(w, http.StatusServiceUnavailable, "nac unavailable")
		return
	}
	sess := mustSess(r)
	var in nac.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := s.nac.Put(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleNACTest(w http.ResponseWriter, r *http.Request) {
	if s.nac == nil {
		writeErr(w, http.StatusServiceUnavailable, "nac unavailable")
		return
	}
	resp, err := s.nac.Test(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": resp})
}
