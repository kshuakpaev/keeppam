package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/policy"
)

func (s *Server) handleCommandPreview(w http.ResponseWriter, r *http.Request) {
	var in policy.CommandPreviewInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(in.Command) == "" {
		writeErr(w, http.StatusBadRequest, "command required")
		return
	}
	out, err := s.policy.PreviewCommand(r.Context(), in)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "pack not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListCommandPacks(w http.ResponseWriter, r *http.Request) {
	list, err := s.policy.ListCommandPacks(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"packs": list})
}

func (s *Server) handleGetCommandPack(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.policy.GetCommandPack(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleCreateCommandPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in policy.CommandPackInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.policy.CreateCommandPack(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleUpdateCommandPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in policy.CommandPackInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.policy.UpdateCommandPack(r.Context(), sess.UserID, id, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeleteCommandPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.policy.DeleteCommandPack(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent()); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleImportCommandPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	merge := r.URL.Query().Get("merge") == "1" || r.URL.Query().Get("merge") == "true"
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	var data []byte
	filename := r.URL.Query().Get("filename")

	switch {
	case strings.HasPrefix(ct, "multipart/"):
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			writeErr(w, http.StatusBadRequest, "multipart: "+err.Error())
			return
		}
		if v := r.FormValue("merge"); v == "1" || v == "true" {
			merge = true
		}
		f, hdr, err := r.FormFile("file")
		if err != nil {
			writeErr(w, http.StatusBadRequest, "file required")
			return
		}
		defer f.Close()
		if hdr != nil {
			filename = hdr.Filename
		}
		data, err = io.ReadAll(io.LimitReader(f, 4<<20))
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	case strings.HasPrefix(ct, "application/json"):
		var body struct {
			Merge    bool     `json:"merge"`
			Filename string   `json:"filename"`
			Text     string   `json:"text"`
			Patterns []string `json:"patterns"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		merge = merge || body.Merge
		if body.Filename != "" {
			filename = body.Filename
		}
		if len(body.Patterns) > 0 {
			raw, _ := json.Marshal(body.Patterns)
			data = raw
			if filename == "" {
				filename = "import.json"
			}
		} else {
			data = []byte(body.Text)
		}
	default:
		var err error
		data, err = io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if filename == "" {
			if strings.Contains(ct, "csv") {
				filename = "import.csv"
			} else if strings.Contains(ct, "json") {
				filename = "import.json"
			} else {
				filename = "import.txt"
			}
		}
	}

	out, err := s.policy.ImportCommandPackPatterns(r.Context(), sess.UserID, id, data, filename, merge, s.clientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListSQLPacks(w http.ResponseWriter, r *http.Request) {
	list, err := s.policy.ListSQLPacks(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"packs": list})
}

func (s *Server) handleGetSQLPack(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.policy.GetSQLPack(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleCreateSQLPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in policy.SQLPackInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.policy.CreateSQLPack(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleUpdateSQLPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in policy.SQLPackInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.policy.UpdateSQLPack(r.Context(), sess.UserID, id, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeleteSQLPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.policy.DeleteSQLPack(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent()); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListHTTPPacks(w http.ResponseWriter, r *http.Request) {
	list, err := s.policy.ListHTTPPacks(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"packs": list})
}

func (s *Server) handleGetHTTPPack(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.policy.GetHTTPPack(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleCreateHTTPPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in policy.HTTPPackInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.policy.CreateHTTPPack(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleUpdateHTTPPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in policy.HTTPPackInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.policy.UpdateHTTPPack(r.Context(), sess.UserID, id, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeleteHTTPPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.policy.DeleteHTTPPack(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent()); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAppObjectPreview(w http.ResponseWriter, r *http.Request) {
	var in policy.AppObjectPreviewInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(in.Method) == "" {
		in.Method = "GET"
	}
	if strings.TrimSpace(in.Path) == "" {
		writeErr(w, http.StatusBadRequest, "path required")
		return
	}
	out, err := s.policy.PreviewAppObject(r.Context(), in)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "pack not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListAppObjectPacks(w http.ResponseWriter, r *http.Request) {
	list, err := s.policy.ListAppObjectPacks(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"packs": list})
}

func (s *Server) handleGetAppObjectPack(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.policy.GetAppObjectPack(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleCreateAppObjectPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in policy.AppObjectPackInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.policy.CreateAppObjectPack(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleUpdateAppObjectPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in policy.AppObjectPackInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.policy.UpdateAppObjectPack(r.Context(), sess.UserID, id, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeleteAppObjectPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.policy.DeleteAppObjectPack(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent()); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) resolveSQLPack(ctx context.Context, userID, assetID uuid.UUID, roles []string, bypass bool, ticketID string) (policy.SQLPack, bool) {
	ev, err := s.policy.Evaluate(ctx, policy.AccessCheck{
		UserID: userID, AssetID: assetID, RoleNames: roles, Bypass: bypass, TicketID: ticketID, SkipRisk: true,
	})
	if err != nil || !ev.OK || ev.SQLPolicyPackID == nil {
		return policy.SQLPack{}, false
	}
	pack, err := s.policy.GetSQLPack(ctx, *ev.SQLPolicyPackID)
	if err != nil {
		return policy.SQLPack{}, false
	}
	return pack, true
}
