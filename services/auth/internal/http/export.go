package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/sessionsvc"
)

func (s *Server) handleExportMP4(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	row, err := s.sessionsvc.Get(r.Context(), id)
	if err != nil {
		if sessionsvc.IsNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !canViewSession(sess.Permissions, sess.UserID, row.UserID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if row.Protocol != "rdp" && row.Protocol != "vnc" {
		writeErr(w, http.StatusBadRequest, "MP4 export is only for rdp/vnc")
		return
	}
	if s.cfg.GuacencURL == "" {
		writeErr(w, http.StatusServiceUnavailable, "guacenc encoder is not configured")
		return
	}
	src, err := s.sessionsvc.RecordingFile(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	mp4 := src + ".mp4"
	if st, err := os.Stat(mp4); err == nil && st.Size() > 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ready",
			"url":    fmt.Sprintf("/api/v1/admin/sessions/%s/recording.mp4", id.String()),
		})
		return
	}

	body, _ := json.Marshal(map[string]string{"path": src})
	client := &http.Client{Timeout: 15 * time.Minute}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.cfg.GuacencURL+"/encode", bytes.NewReader(body))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "encoder unreachable: "+err.Error())
		return
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var enc struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Detail string `json:"detail"`
		MP4    string `json:"mp4"`
	}
	_ = json.Unmarshal(raw, &enc)
	if res.StatusCode >= 300 {
		msg := enc.Error
		if msg == "" {
			msg = string(raw)
		}
		if enc.Detail != "" {
			msg = msg + ": " + enc.Detail
		}
		writeErr(w, http.StatusBadGateway, msg)
		return
	}
	if _, err := os.Stat(mp4); err != nil {
		writeErr(w, http.StatusBadGateway, "encoder finished but mp4 missing")
		return
	}
	_ = s.audit.Record(r.Context(), &sess.UserID, "session.export_mp4", "session", id.String(), clientIP(r), r.UserAgent(), map[string]any{
		"path": mp4,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ready",
		"url":    fmt.Sprintf("/api/v1/admin/sessions/%s/recording.mp4", id.String()),
	})
}

func (s *Server) handleGetRecordingMP4(w http.ResponseWriter, r *http.Request) {
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
	if !canViewSession(sess.Permissions, sess.UserID, row.UserID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if row.Protocol != "rdp" && row.Protocol != "vnc" {
		writeErr(w, http.StatusBadRequest, "MP4 available only for rdp/vnc")
		return
	}
	src, err := s.sessionsvc.RecordingFile(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	mp4 := src + ".mp4"
	if _, err := os.Stat(mp4); err != nil {
		writeErr(w, http.StatusNotFound, "mp4 not ready; call export-mp4 first")
		return
	}
	w.Header().Set("Content-Type", "video/mp4")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", id.String()+".mp4"))
	http.ServeFile(w, r, mp4)
}
