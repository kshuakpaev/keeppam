package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/keeppam/auth/internal/residency"
)

func (s *Server) residencySvc() *residency.Service {
	if s.settings == nil {
		return nil
	}
	return residency.New(s.settings.DB(), s.audit)
}

func (s *Server) residencyView(w http.ResponseWriter, st residency.Settings) {
	st.AttachCompliance(s.cfg.DataKeySource, s.cfg.S3Endpoint)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleGetResidency(w http.ResponseWriter, r *http.Request) {
	svc := s.residencySvc()
	if svc == nil {
		writeErr(w, http.StatusServiceUnavailable, "residency unavailable")
		return
	}
	st, err := svc.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.residencyView(w, st)
}

func (s *Server) handlePutResidency(w http.ResponseWriter, r *http.Request) {
	svc := s.residencySvc()
	if svc == nil {
		writeErr(w, http.StatusServiceUnavailable, "residency unavailable")
		return
	}
	sess := mustSess(r)
	var in residency.UpdateInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := svc.Update(r.Context(), sess.UserID, in, s.cfg.DataKeySource, s.cfg.S3Endpoint, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
