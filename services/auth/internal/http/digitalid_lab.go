package httpapi

import (
	"net/http"

	"github.com/keeppam/auth/internal/digitalidlab"
)

func (s *Server) labOr404(w http.ResponseWriter) *digitalidlab.Lab {
	if s == nil || s.didLab == nil {
		writeErr(w, http.StatusNotFound, "Digital ID lab IdP disabled (KEEPPAM_DIGITALID_LAB)")
		return nil
	}
	return s.didLab
}

func (s *Server) handleDigitalIDLabAuthorize(w http.ResponseWriter, r *http.Request) {
	lab := s.labOr404(w)
	if lab == nil {
		return
	}
	lab.HandleAuthorize(w, r)
}

func (s *Server) handleDigitalIDLabToken(w http.ResponseWriter, r *http.Request) {
	lab := s.labOr404(w)
	if lab == nil {
		return
	}
	lab.HandleToken(w, r)
}

func (s *Server) handleDigitalIDLabUserinfo(w http.ResponseWriter, r *http.Request) {
	lab := s.labOr404(w)
	if lab == nil {
		return
	}
	lab.HandleUserinfo(w, r)
}

func (s *Server) handleDigitalIDLabPreset(w http.ResponseWriter, r *http.Request) {
	if s.didLab == nil {
		writeErr(w, http.StatusNotFound, "Digital ID lab IdP disabled (KEEPPAM_DIGITALID_LAB)")
		return
	}
	cfg, _, _, err := s.settings.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	base := cfg.PublicBaseURL
	if base == "" {
		base = s.cfg.CORSOrigin
	}
	writeJSON(w, http.StatusOK, digitalidlab.MakePreset(base, s.cfg.HTTPAddr))
}
