package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	options, err := s.auth.BeginWebAuthnRegister(r.Context(), sess.UserID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, options)
}

func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var body struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Credential) == 0 {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	cred, err := s.auth.FinishWebAuthnRegister(r.Context(), sess.UserID, body.Name, body.Credential, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":         cred.ID,
		"name":       cred.Name,
		"created_at": cred.CreatedAt,
	})
}

func (s *Server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChallengeToken string `json:"challenge_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ChallengeToken == "" {
		writeErr(w, http.StatusBadRequest, "challenge_token required")
		return
	}
	options, err := s.auth.BeginWebAuthnLogin(r.Context(), body.ChallengeToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, options)
}

func (s *Server) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	var body struct {
		ChallengeToken string          `json:"challenge_token"`
		Credential     json.RawMessage `json:"credential"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.ChallengeToken == "" || len(body.Credential) == 0 {
		writeErr(w, http.StatusBadRequest, "challenge_token and credential required")
		return
	}
	res, err := s.auth.FinishWebAuthnLogin(r.Context(), body.ChallengeToken, body.Credential, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := s.completeLogin(w, r, res.SessionToken, "WEBAUTHN"); err != nil {
		writeErr(w, http.StatusInternalServerError, "session cookie")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleListMyWebAuthn(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	creds, err := s.auth.ListWebAuthnCredentials(r.Context(), sess.UserID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type item struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}
	out := make([]item, 0, len(creds))
	for _, c := range creds {
		out = append(out, item{ID: c.ID.String(), Name: c.Name, CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": out})
}

func (s *Server) handleDeleteMyWebAuthn(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	credID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.auth.DeleteWebAuthnCredential(r.Context(), sess.UserID, sess.UserID, credID, clientIP(r), r.UserAgent()); err != nil {
		if err == pgx.ErrNoRows {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListUserWebAuthn(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	creds, err := s.auth.ListWebAuthnCredentials(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type item struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}
	out := make([]item, 0, len(creds))
	for _, c := range creds {
		out = append(out, item{ID: c.ID.String(), Name: c.Name, CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": out})
}
