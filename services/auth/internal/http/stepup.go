package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/session"
)

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

func (s *Server) writeStepUpChallenge(w http.ResponseWriter, r *http.Request, sess session.Session, ev policy.AccessResult, assetID uuid.UUID) {
	tok, methods, err := s.auth.BeginStepUp(r.Context(), sess.UserID, sess.Username, assetID)
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
	_ = s.audit.Record(r.Context(), &sess.UserID, "access.stepup.challenged", "asset", assetID.String(), s.clientIP(r), r.UserAgent(), payload)
	factors := ev.RiskFactors
	if factors == nil {
		factors = []string{}
	}
	writeErrFields(w, http.StatusForbidden, ev.RiskDenyMessage(), map[string]any{
		"code":            "mfa_required",
		"challenge_token": tok,
		"totp":            methods.TOTP,
		"webauthn":        methods.WebAuthn,
		"risk_score":      ev.RiskScore,
		"max_risk":        ev.MaxRisk,
		"risk_factors":    factors,
		"risk_action":     ev.RiskAction,
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
