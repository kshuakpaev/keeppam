package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/sessionsvc"
)

func (s *Server) handleGetTranscript(w http.ResponseWriter, r *http.Request) {
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
	indexed, _ := s.sessionsvc.TranscriptIndexed(r.Context(), id)
	lines, err := s.sessionsvc.ListCommandTranscript(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	output, _ := s.sessionsvc.ListOutputTranscript(r.Context(), id)
	keys, _ := s.sessionsvc.ListKeystrokeTranscript(r.Context(), id)
	screen, _ := s.sessionsvc.ListScreenTextTranscript(r.Context(), id)
	files, _ := s.sessionsvc.ListFileTranscript(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{
		"indexed": indexed, "protocol": row.Protocol, "lines": lines, "output": output, "keystrokes": keys, "screen_text": screen,
		"files": files, "window_titles": sessionsvc.WindowTitlesFromScreen(screen),
	})
}

func (s *Server) handleIndexTranscript(w http.ResponseWriter, r *http.Request) {
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
	if s.castidx == nil {
		writeErr(w, http.StatusServiceUnavailable, "indexer unavailable")
		return
	}
	force := false
	ocr := false
	if r.Body != nil {
		var body struct {
			Force bool `json:"force"`
			OCR   bool `json:"ocr"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		force = body.Force
		ocr = body.OCR
	}
	out, err := s.castidx.Index(r.Context(), id, force)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var ocrOut any
	if ocr {
		if row.Protocol == "rdp" || row.Protocol == "vnc" || row.Isolated {
			ocrRes, ocrErr := s.castidx.IndexOCR(r.Context(), id, force)
			if ocrErr != nil {
				writeErr(w, http.StatusBadGateway, ocrErr.Error())
				return
			}
			ocrOut = ocrRes
		} else {
			ocrOut = map[string]string{"skipped": "unsupported"}
		}
	}
	lines, _ := s.sessionsvc.ListCommandTranscript(r.Context(), id)
	output, _ := s.sessionsvc.ListOutputTranscript(r.Context(), id)
	keys, _ := s.sessionsvc.ListKeystrokeTranscript(r.Context(), id)
	screen, _ := s.sessionsvc.ListScreenTextTranscript(r.Context(), id)
	files, _ := s.sessionsvc.ListFileTranscript(r.Context(), id)
	resp := map[string]any{
		"result": out, "lines": lines, "output": output, "keystrokes": keys, "screen_text": screen,
		"files": files, "window_titles": sessionsvc.WindowTitlesFromScreen(screen),
	}
	if ocrOut != nil {
		resp["ocr"] = ocrOut
	}
	writeJSON(w, http.StatusOK, resp)
}
