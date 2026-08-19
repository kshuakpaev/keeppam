package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/keeppam/auth/internal/recarch"
)

func (s *Server) handleGetArchiveSettings(w http.ResponseWriter, r *http.Request) {
	if s.archive == nil {
		writeErr(w, http.StatusServiceUnavailable, "archive unavailable")
		return
	}
	st, err := s.archive.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	st.SMBPassword = ""
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handlePutArchiveSettings(w http.ResponseWriter, r *http.Request) {
	if s.archive == nil {
		writeErr(w, http.StatusServiceUnavailable, "archive unavailable")
		return
	}
	sess := mustSess(r)
	var in recarch.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := s.archive.Update(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out.SMBPassword = ""
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleArchiveSync(w http.ResponseWriter, r *http.Request) {
	if s.archive == nil {
		writeErr(w, http.StatusServiceUnavailable, "archive unavailable")
		return
	}
	stats, err := s.archive.SyncOnce(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
