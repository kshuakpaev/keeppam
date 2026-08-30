package httpapi

import (
	"net/http"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/rbac"
)

func (s *Server) handleListSessionFiles(w http.ResponseWriter, r *http.Request) {
	if s.files == nil {
		writeJSON(w, http.StatusOK, map[string]any{"files": []any{}})
		return
	}
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
	if !s.sessionVisible(r.Context(), sess, row) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	list, err := s.files.List(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": list})
}

func (s *Server) handleGetSessionFile(w http.ResponseWriter, r *http.Request) {
	if s.files == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	fid, err := uuid.Parse(chi.URLParam(r, "fileId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid file id")
		return
	}
	row, err := s.sessionsvc.Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !s.sessionVisible(r.Context(), sess, row) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if !rbac.HasPermission(sess.Permissions, "sessions.files.read") {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	f, err := s.files.Get(r.Context(), id, fid)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	fh, err := s.files.OpenLocal(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	defer fh.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(f.Filename)+`"`)
	http.ServeContent(w, r, f.Filename, f.CreatedAt, fh)
}
