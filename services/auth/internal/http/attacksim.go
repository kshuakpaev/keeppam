package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) handleListAttackScenarios(w http.ResponseWriter, r *http.Request) {
	if s.attacksim == nil {
		writeErr(w, http.StatusServiceUnavailable, "attacksim unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scenarios": s.attacksim.ListScenarios()})
}

func (s *Server) handleListAttackRuns(w http.ResponseWriter, r *http.Request) {
	list, err := s.attacksim.ListRuns(r.Context(), 30)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": list})
}

func (s *Server) handleGetAttackRun(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	run, err := s.attacksim.GetRun(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleStartAttackRun(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var body struct {
		Notes string `json:"notes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	run, err := s.attacksim.Run(r.Context(), sess.UserID, body.Notes)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, run)
}
