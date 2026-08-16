package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/session"
	"github.com/keeppam/auth/internal/sessionsvc"
)

const opStepUpWait = 60 * time.Second

func writeErrFields(w http.ResponseWriter, code int, msg string, extra map[string]any) {
	m := map[string]any{"error": msg}
	for k, v := range extra {
		m[k] = v
	}
	writeJSON(w, code, m)
}

func (s *Server) consumeStepUp(r *http.Request, userID, assetID uuid.UUID, token string) bool {
	if token == "" {
		return false
	}
	return s.auth.ConsumeStepUp(r.Context(), token, userID, assetID) == nil
}

func (s *Server) writeStepUpChallenge(w http.ResponseWriter, r *http.Request, sess session.Session, ev policy.AccessResult, assetID, sessionID uuid.UUID) {
	pending, err := s.armOpStepUp(r.Context(), sess.UserID, sess.Username, assetID, sessionID, ev)
	payload := map[string]any{"reason": "risk"}
	ev.FillDenyPayload(payload)
	if err != nil {
		_ = s.audit.Record(r.Context(), &sess.UserID, "session.denied", "asset", assetID.String(), s.clientIP(r), r.UserAgent(), payload)
		writeErrFields(w, http.StatusForbidden, "step-up MFA required but MFA is not enrolled", map[string]any{
			"code":         "mfa_not_enrolled",
			"risk_score":   ev.RiskScore,
			"max_risk":     ev.MaxRisk,
			"risk_factors": ev.RiskFactors,
			"risk_action":  ev.RiskAction,
		})
		return
	}
	payload["code"] = "mfa_required"
	if ev.Operation != "" {
		payload["operation"] = ev.Operation
	}
	_ = s.audit.Record(r.Context(), &sess.UserID, "access.stepup.challenged", "asset", assetID.String(), s.clientIP(r), r.UserAgent(), payload)
	writeErrFields(w, http.StatusForbidden, ev.RiskDenyMessage(), stepUpFields(pending, ev))
}

func stepUpFields(p session.OpStepUpPending, ev policy.AccessResult) map[string]any {
	factors := p.RiskFactors
	if factors == nil {
		factors = ev.RiskFactors
	}
	if factors == nil {
		factors = []string{}
	}
	return map[string]any{
		"code":            "mfa_required",
		"challenge_token": p.ChallengeToken,
		"totp":            p.TOTP,
		"webauthn":        p.WebAuthn,
		"risk_score":      ev.RiskScore,
		"max_risk":        ev.MaxRisk,
		"risk_factors":    factors,
		"risk_action":     ev.RiskAction,
		"operation":       ev.Operation,
	}
}

func (s *Server) armOpStepUp(ctx context.Context, userID uuid.UUID, username string, assetID, sessionID uuid.UUID, ev policy.AccessResult) (session.OpStepUpPending, error) {
	if sessionID != uuid.Nil {
		if p, ok := s.auth.GetOpStepUpPending(ctx, sessionID); ok {
			if _, err := s.sessions.GetChallenge(ctx, p.ChallengeToken); err == nil {
				return p, nil
			}
		}
	}
	tok, methods, err := s.auth.BeginStepUp(ctx, userID, username, assetID, sessionID)
	if err != nil {
		return session.OpStepUpPending{}, err
	}
	factors := ev.RiskFactors
	if factors == nil {
		factors = []string{}
	}
	p := session.OpStepUpPending{
		ChallengeToken: tok, TOTP: methods.TOTP, WebAuthn: methods.WebAuthn,
		RiskScore: ev.RiskScore, MaxRisk: ev.MaxRisk, RiskFactors: factors, Operation: ev.Operation,
	}
	if sessionID != uuid.Nil {
		_ = s.auth.PutOpStepUpPending(ctx, sessionID, p)
	}
	return p, nil
}

func (s *Server) waitOpStepUp(ctx context.Context, row sessionsvc.Session, ev policy.AccessResult) bool {
	if s.auth == nil {
		return false
	}
	if s.auth.HasOpStepUp(ctx, row.ID, row.UserID) {
		return true
	}
	if _, err := s.armOpStepUp(ctx, row.UserID, row.Username, row.AssetID, row.ID, ev); err != nil {
		return false
	}
	deadline := time.Now().Add(opStepUpWait)
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		if s.auth.HasOpStepUp(ctx, row.ID, row.UserID) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return s.auth.HasOpStepUp(context.Background(), row.ID, row.UserID)
		case <-ticker.C:
		}
	}
}

func (s *Server) handleGetOpStepUp(w http.ResponseWriter, r *http.Request) {
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
	if row.UserID != sess.UserID {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if s.auth.HasOpStepUp(r.Context(), id, sess.UserID) {
		writeJSON(w, http.StatusOK, map[string]any{"pending": false, "granted": true})
		return
	}
	p, ok := s.auth.GetOpStepUpPending(r.Context(), id)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"pending": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pending": true, "granted": false,
		"code": "mfa_required", "challenge_token": p.ChallengeToken,
		"totp": p.TOTP, "webauthn": p.WebAuthn,
		"risk_score": p.RiskScore, "max_risk": p.MaxRisk, "risk_factors": p.RiskFactors,
		"operation": p.Operation,
	})
}

func (s *Server) handleStepUpTOTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChallengeToken string `json:"challenge_token"`
		Code           string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ChallengeToken == "" || body.Code == "" {
		writeErr(w, http.StatusBadRequest, "challenge_token and code required")
		return
	}
	res, err := s.auth.VerifyStepUpTOTP(r.Context(), body.ChallengeToken, body.Code, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleStepUpWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleStepUpWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
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
	res, err := s.auth.FinishStepUpWebAuthn(r.Context(), body.ChallengeToken, body.Credential, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func isStepUpErr(err error) (*policy.StepUpError, bool) {
	var se *policy.StepUpError
	if errors.As(err, &se) {
		return se, true
	}
	return nil, false
}