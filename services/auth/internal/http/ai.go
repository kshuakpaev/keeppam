package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/ai"
	"github.com/keeppam/auth/internal/rbac"
)

func (s *Server) requireAI(w http.ResponseWriter) bool {
	if s.ai == nil {
		writeErr(w, http.StatusServiceUnavailable, "ai unavailable")
		return false
	}
	if !s.ai.Licensed() {
		writeErrFields(w, http.StatusForbidden, "license", map[string]any{"code": "license"})
		return false
	}
	return true
}

func (s *Server) handleGetAISettings(w http.ResponseWriter, r *http.Request) {
	if s.ai == nil {
		writeErr(w, http.StatusServiceUnavailable, "ai unavailable")
		return
	}
	cfg, err := s.ai.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handlePutAISettings(w http.ResponseWriter, r *http.Request) {
	if s.ai == nil {
		writeErr(w, http.StatusServiceUnavailable, "ai unavailable")
		return
	}
	sess := mustSess(r)
	var in ai.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := s.ai.Put(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAITest(w http.ResponseWriter, r *http.Request) {
	if !s.requireAI(w) {
		return
	}
	res, err := s.ai.Test(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleGetAISummary(w http.ResponseWriter, r *http.Request) {
	if !s.requireAI(w) {
		return
	}
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
	sess := mustSess(r)
	if !s.sessionVisible(r.Context(), sess, row) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	sum, err := s.ai.GetSummary(r.Context(), id)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusOK, map[string]any{"status": "skipped", "skip_reason": "none", "session_id": id})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) handlePostAISummary(w http.ResponseWriter, r *http.Request) {
	if !s.requireAI(w) {
		return
	}
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
	sess := mustSess(r)
	if !s.sessionVisible(r.Context(), sess, row) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var body struct {
		Force bool `json:"force"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	sum, err := s.ai.RequestSummary(r.Context(), id, body.Force)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) handleGetAIRisk(w http.ResponseWriter, r *http.Request) {
	if !s.requireAI(w) {
		return
	}
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
	sess := mustSess(r)
	if !s.sessionVisible(r.Context(), sess, row) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	out, err := s.ai.GetRisk(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetAIBrief(w http.ResponseWriter, r *http.Request) {
	if !s.requireAI(w) {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	sess := mustSess(r)
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	if kind == "" {
		kind = ai.BriefJIT
	}
	switch kind {
	case ai.BriefJIT:
		if !rbac.HasPermission(sess.Permissions, "access.approve") && !rbac.HasPermission(sess.Permissions, "access.approve.security") {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
	case ai.BriefSupervisor:
		if !rbac.HasPermission(sess.Permissions, "sessions.supervise") {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
	case ai.BriefCommand:
		if !rbac.HasPermission(sess.Permissions, "access.approve") {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "invalid kind")
		return
	}
	out, err := s.ai.GetBrief(r.Context(), kind, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleJEADraft(w http.ResponseWriter, r *http.Request) {
	if !s.requireAI(w) {
		return
	}
	var in struct {
		Prompt string `json:"prompt"`
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Prompt) == "" {
		writeErr(w, http.StatusBadRequest, "prompt required")
		return
	}
	out, err := s.ai.DraftJEA(r.Context(), in.Prompt, in.UserID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetOpAIBrief(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	q.Set("kind", ai.BriefCommand)
	r.URL.RawQuery = q.Encode()
	s.handleGetAIBrief(w, r)
}

func (s *Server) handleGetSessionAIBrief(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("kind") == "" {
		q.Set("kind", ai.BriefSupervisor)
	}
	r.URL.RawQuery = q.Encode()
	s.handleGetAIBrief(w, r)
}

func (s *Server) handleHelpAsk(w http.ResponseWriter, r *http.Request) {
	if s.ai == nil {
		writeErr(w, http.StatusServiceUnavailable, "ai unavailable")
		return
	}
	var in struct {
		Q string `json:"q"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Q) == "" {
		writeErr(w, http.StatusBadRequest, "q required")
		return
	}
	out, err := s.ai.HelpAsk(r.Context(), in.Q)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
