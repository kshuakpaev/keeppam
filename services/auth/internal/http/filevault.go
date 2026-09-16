package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/filevault"
	"github.com/keeppam/auth/internal/rbac"
)

func (s *Server) handleListProtectedFiles(w http.ResponseWriter, r *http.Request) {
	if s.filevault == nil {
		writeJSON(w, http.StatusOK, map[string]any{"files": []any{}})
		return
	}
	sess := mustSess(r)
	custodian := rbac.HasPermission(sess.Permissions, "files.vault.write")
	list, err := s.filevault.List(r.Context(), sess.UserID, custodian)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": list})
}

func (s *Server) handleUploadProtectedFile(w http.ResponseWriter, r *http.Request) {
	if s.filevault == nil {
		writeErr(w, http.StatusServiceUnavailable, "file vault unavailable")
		return
	}
	sess := mustSess(r)
	if err := r.ParseMultipartForm(filevault.MaxBytes + 1<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "multipart required")
		return
	}
	fh, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "file field required")
		return
	}
	defer fh.Close()
	raw, err := io.ReadAll(io.LimitReader(fh, filevault.MaxBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctype := hdr.Header.Get("Content-Type")
	name := r.FormValue("name")
	if name == "" {
		name = hdr.Filename
	}
	f, err := s.filevault.Upload(r.Context(), sess.UserID, name, r.FormValue("description"), ctype, raw, s.clientIP(r), r.UserAgent())
	if err != nil {
		code := http.StatusBadRequest
		if err == filevault.ErrTooLarge {
			code = http.StatusRequestEntityTooLarge
		}
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, f)
}

func (s *Server) handleDeleteProtectedFile(w http.ResponseWriter, r *http.Request) {
	if s.filevault == nil {
		writeErr(w, http.StatusServiceUnavailable, "file vault unavailable")
		return
	}
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.filevault.Delete(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent()); err != nil {
		if err == pgx.ErrNoRows {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleRequestProtectedFile(w http.ResponseWriter, r *http.Request) {
	if s.filevault == nil {
		writeErr(w, http.StatusServiceUnavailable, "file vault unavailable")
		return
	}
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var body struct {
		Reason     string `json:"reason"`
		TTLMinutes int    `json:"ttl_minutes"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	g, err := s.filevault.Request(r.Context(), sess.UserID, id, strings.TrimSpace(body.Reason), body.TTLMinutes, s.clientIP(r), r.UserAgent())
	if err != nil {
		if err == pgx.ErrNoRows {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) handleListFileGrants(w http.ResponseWriter, r *http.Request) {
	if s.filevault == nil {
		writeJSON(w, http.StatusOK, map[string]any{"grants": []any{}})
		return
	}
	_ = s.filevault.ExpireStale(r.Context())
	pending := r.URL.Query().Get("pending") == "1"
	list, err := s.filevault.ListGrants(r.Context(), pending)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": list})
}

func (s *Server) handleDecideFileGrant(w http.ResponseWriter, r *http.Request) {
	if s.filevault == nil {
		writeErr(w, http.StatusServiceUnavailable, "file vault unavailable")
		return
	}
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	approve := strings.HasSuffix(r.URL.Path, "/approve")
	g, err := s.filevault.Decide(r.Context(), sess.UserID, id, approve, s.clientIP(r), r.UserAgent())
	if err != nil {
		code := http.StatusBadRequest
		if err == pgx.ErrNoRows {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) handleDownloadProtectedFile(w http.ResponseWriter, r *http.Request) {
	if s.filevault == nil {
		writeErr(w, http.StatusServiceUnavailable, "file vault unavailable")
		return
	}
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	custodian := rbac.HasPermission(sess.Permissions, "files.vault.write")
	f, raw, err := s.filevault.Download(r.Context(), sess.UserID, id, custodian, s.clientIP(r), r.UserAgent())
	if err != nil {
		code := http.StatusForbidden
		if err == pgx.ErrNoRows {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	w.Header().Set("Content-Type", f.ContentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(f.Name, `"`, "")+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(raw)), 10))
	_, _ = w.Write(raw)
}
