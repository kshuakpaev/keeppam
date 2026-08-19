package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/sessionsvc"
)

func (s *Server) rejectIfWaitingSupervisor(w http.ResponseWriter, row sessionsvc.Session) bool {
	if row.IsWaitingSupervisor() {
		writeErr(w, http.StatusConflict, "waiting for supervisor")
		return true
	}
	return false
}

func (s *Server) handleApproveSupervisor(w http.ResponseWriter, r *http.Request) {
	s.decideSupervisor(w, r, true)
}

func (s *Server) handleDenySupervisor(w http.ResponseWriter, r *http.Request) {
	s.decideSupervisor(w, r, false)
}

func (s *Server) decideSupervisor(w http.ResponseWriter, r *http.Request, approve bool) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	row, err := s.sessionsvc.Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if row.SupervisorGroupID != nil && s.policy != nil {
		ok, gerr := s.policy.UserInGroup(r.Context(), sess.UserID, *row.SupervisorGroupID)
		if gerr != nil {
			writeErr(w, http.StatusInternalServerError, gerr.Error())
			return
		}
		if !ok {
			writeErr(w, http.StatusForbidden, "not a member of the supervisor group")
			return
		}
	}
	var out sessionsvc.Session
	if approve {
		out, err = s.sessionsvc.ApproveSupervisor(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent())
	} else {
		out, err = s.sessionsvc.DenySupervisor(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent())
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.notify != nil {
		s.notify.OnSupervisorDecided(r.Context(), out, approve)
	}
	writeJSON(w, http.StatusOK, out)
}
