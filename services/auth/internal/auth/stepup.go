package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/session"
)

const stepUpPurpose = "stepup"

type MFAMethods struct {
	TOTP     bool `json:"totp"`
	WebAuthn bool `json:"webauthn"`
}

type StepUpResult struct {
	StepUpToken string `json:"step_up_token"`
}

func (s *Service) MFAMethods(ctx context.Context, userID uuid.UUID) (MFAMethods, error) {
	u, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return MFAMethods{}, err
	}
	n, err := s.db.CountWebAuthnCredentials(ctx, userID)
	if err != nil {
		return MFAMethods{}, err
	}
	return MFAMethods{
		TOTP:     len(u.MFASecretEnc) > 0,
		WebAuthn: n > 0,
	}, nil
}

func (s *Service) BeginStepUp(ctx context.Context, userID uuid.UUID, username string, assetID, sessionID uuid.UUID) (string, MFAMethods, error) {
	methods, err := s.MFAMethods(ctx, userID)
	if err != nil {
		return "", methods, err
	}
	if !methods.TOTP && !methods.WebAuthn {
		return "", methods, fmt.Errorf("mfa not enrolled")
	}
	chal := session.Challenge{
		UserID: userID, Username: username, Purpose: stepUpPurpose, AssetID: assetID.String(),
	}
	if sessionID != uuid.Nil {
		chal.SessionID = sessionID.String()
	}
	tok, err := s.sessions.CreateChallenge(ctx, chal, s.cfg.ChallengeTTL)
	if err != nil {
		return "", methods, err
	}
	return tok, methods, nil
}

func (s *Service) issueStepUpGrant(ctx context.Context, userID, assetID uuid.UUID) (string, error) {
	grantTok, err := session.CSRFToken()
	if err != nil {
		return "", err
	}
	if err := s.sessions.PutJSON(ctx, "stepup:"+grantTok, session.StepUpGrant{UserID: userID, AssetID: assetID}, 2*time.Minute); err != nil {
		return "", err
	}
	return grantTok, nil
}

func parseChallengeAsset(chal session.Challenge) (uuid.UUID, error) {
	id, err := uuid.Parse(chal.AssetID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid challenge")
	}
	return id, nil
}

func (s *Service) VerifyStepUpTOTP(ctx context.Context, challengeToken, code, ip, ua string) (StepUpResult, error) {
	chal, err := s.sessions.GetChallenge(ctx, challengeToken)
	if err != nil || chal.Purpose != stepUpPurpose {
		return StepUpResult{}, fmt.Errorf("invalid challenge")
	}
	assetID, err := parseChallengeAsset(chal)
	if err != nil {
		return StepUpResult{}, err
	}
	if err := s.verifyUserTOTP(ctx, chal.UserID, code, ip, ua, "http"); err != nil {
		return StepUpResult{}, err
	}
	_ = s.sessions.DeleteChallenge(ctx, challengeToken)
	s.bindOpGrant(ctx, chal)
	tok, err := s.issueStepUpGrant(ctx, chal.UserID, assetID)
	if err != nil {
		return StepUpResult{}, err
	}
	_ = s.audit.Record(ctx, &chal.UserID, "access.stepup.ok", "asset", assetID.String(), ip, ua, map[string]any{"method": "totp"})
	return StepUpResult{StepUpToken: tok}, nil
}

func (s *Service) FinishStepUpWebAuthn(ctx context.Context, challengeToken string, credentialJSON []byte, ip, ua string) (StepUpResult, error) {
	chal, err := s.sessions.GetChallenge(ctx, challengeToken)
	if err != nil || chal.Purpose != stepUpPurpose {
		return StepUpResult{}, fmt.Errorf("invalid challenge")
	}
	assetID, err := parseChallengeAsset(chal)
	if err != nil {
		return StepUpResult{}, err
	}
	if _, err := s.finishWebAuthnAssertion(ctx, challengeToken, credentialJSON, ip, ua, false); err != nil {
		return StepUpResult{}, err
	}
	_ = s.sessions.DeleteChallenge(ctx, challengeToken)
	s.bindOpGrant(ctx, chal)
	tok, err := s.issueStepUpGrant(ctx, chal.UserID, assetID)
	if err != nil {
		return StepUpResult{}, err
	}
	_ = s.audit.Record(ctx, &chal.UserID, "access.stepup.ok", "asset", assetID.String(), ip, ua, map[string]any{"method": "webauthn"})
	return StepUpResult{StepUpToken: tok}, nil
}

func (s *Service) ConsumeStepUp(ctx context.Context, token string, userID, assetID uuid.UUID) error {
	if token == "" {
		return fmt.Errorf("invalid step-up token")
	}
	var g session.StepUpGrant
	if err := s.sessions.ConsumeJSON(ctx, "stepup:"+token, &g); err != nil {
		return fmt.Errorf("invalid or expired step-up token")
	}
	if g.UserID != userID || g.AssetID != assetID {
		return fmt.Errorf("invalid or expired step-up token")
	}
	return nil
}

func (s *Service) bindOpGrant(ctx context.Context, chal session.Challenge) {
	sid, err := uuid.Parse(chal.SessionID)
	if err != nil || sid == uuid.Nil {
		return
	}
	_ = s.sessions.PutOpStepUp(ctx, sid, chal.UserID)
	s.sessions.ClearOpStepUpPending(ctx, sid)
}

func (s *Service) HasOpStepUp(ctx context.Context, sessionID, userID uuid.UUID) bool {
	if s == nil || s.sessions == nil {
		return false
	}
	return s.sessions.HasOpStepUp(ctx, sessionID, userID)
}

func (s *Service) ClearOpStepUp(ctx context.Context, sessionID uuid.UUID) {
	if s == nil || s.sessions == nil {
		return
	}
	s.sessions.ClearOpStepUp(ctx, sessionID)
}

func (s *Service) PutOpStepUpPending(ctx context.Context, sessionID uuid.UUID, p session.OpStepUpPending) error {
	if s == nil || s.sessions == nil {
		return fmt.Errorf("session store unavailable")
	}
	return s.sessions.PutOpStepUpPending(ctx, sessionID, p)
}

func (s *Service) GetOpStepUpPending(ctx context.Context, sessionID uuid.UUID) (session.OpStepUpPending, bool) {
	if s == nil || s.sessions == nil {
		return session.OpStepUpPending{}, false
	}
	return s.sessions.GetOpStepUpPending(ctx, sessionID)
}

func (s *Service) VerifyUserTOTP(ctx context.Context, userID uuid.UUID, code, ip, ua, via string, assetID uuid.UUID) error {
	if err := s.verifyUserTOTP(ctx, userID, code, ip, ua, via); err != nil {
		return err
	}
	_ = s.audit.Record(ctx, &userID, "access.stepup.ok", "asset", assetID.String(), ip, ua, map[string]any{"method": "totp", "via": via})
	return nil
}

func (s *Service) verifyUserTOTP(ctx context.Context, userID uuid.UUID, code, ip, ua, via string) error {
	u, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if len(u.MFASecretEnc) == 0 {
		return fmt.Errorf("totp not configured")
	}
	secret, err := s.env.Decrypt(u.MFASecretEnc)
	if err != nil {
		return err
	}
	defer crypto.Wipe(secret)
	if !totp.Validate(code, string(secret)) {
		_ = s.audit.Record(ctx, &u.ID, "access.stepup.failure", "user", u.ID.String(), ip, ua, map[string]any{"reason": "invalid_totp", "via": via})
		return fmt.Errorf("invalid mfa code")
	}
	return nil
}
