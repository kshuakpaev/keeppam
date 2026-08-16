package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/keeppam/auth/internal/dr"
)

func (s *Server) handleDRStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.dr.Status(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleGetDRSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.dr.GetSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handlePutDRSettings(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in dr.SettingsInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	st, err := s.dr.PutSettings(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleDRBackup(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	res, err := s.dr.RunBackup(r.Context(), sess.UserID, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDRDrill(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in dr.DrillInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	st, err := s.dr.RecordDrill(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}
