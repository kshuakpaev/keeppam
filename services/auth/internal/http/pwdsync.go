package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
)

func (s *Server) handleListPasswordSets(w http.ResponseWriter, r *http.Request) {
	list, err := s.assets.ListPasswordSets(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []assets.PasswordSet{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sets": list})
}

func (s *Server) handleGetPasswordSet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	set, err := s.assets.GetPasswordSet(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) handleCreatePasswordSet(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in assets.CreatePasswordSetInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	set, err := s.assets.CreatePasswordSet(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, set)
}

func (s *Server) handleUpdatePasswordSet(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in assets.UpdatePasswordSetInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	set, err := s.assets.UpdatePasswordSet(r.Context(), sess.UserID, id, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) handleDeletePasswordSet(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.assets.DeletePasswordSet(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRotatePasswordSet(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in assets.RotateInput
	_ = json.NewDecoder(r.Body).Decode(&in)
	res, err := s.assets.RotatePasswordSet(r.Context(), sess.UserID, id, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
