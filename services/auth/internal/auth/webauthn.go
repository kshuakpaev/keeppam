package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/store"
)

type waUser struct {
	id          uuid.UUID
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte {
	return u.id[:]
}

func (u *waUser) WebAuthnName() string {
	return u.name
}

func (u *waUser) WebAuthnDisplayName() string {
	if u.displayName != "" {
		return u.displayName
	}
	return u.name
}

func (u *waUser) WebAuthnCredentials() []webauthn.Credential {
	return u.creds
}

func (s *Service) webAuthn() (*webauthn.WebAuthn, error) {
	origins := s.cfg.WebAuthnOrigins
	if len(origins) == 0 {
		origins = []string{s.cfg.CORSOrigin}
	}
	rpID := s.cfg.WebAuthnRPID
	if rpID == "" {
		rpID = "localhost"
	}
	return webauthn.New(&webauthn.Config{
		RPDisplayName: s.cfg.WebAuthnRPDisplayName,
		RPID:          rpID,
		RPOrigins:     origins,
	})
}

func (s *Service) loadWAUser(ctx context.Context, userID uuid.UUID) (*waUser, store.User, error) {
	u, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return nil, store.User{}, err
	}
	rows, err := s.db.ListWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, store.User{}, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, c := range rows {
		transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transport))
		for _, t := range c.Transport {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		creds = append(creds, webauthn.Credential{
			ID:              c.CredentialID,
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Transport:       transports,
			Flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: c.BackupEligible,
				BackupState:    c.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		})
	}
	return &waUser{
		id:          u.ID,
		name:        u.Username,
		displayName: u.DisplayName,
		creds:       creds,
	}, u, nil
}

func (s *Service) BeginWebAuthnRegister(ctx context.Context, userID uuid.UUID) (any, error) {
	wa, err := s.webAuthn()
	if err != nil {
		return nil, err
	}
	user, _, err := s.loadWAUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	options, sessionData, err := wa.BeginRegistration(user)
	if err != nil {
		return nil, err
	}
	if err := s.sessions.PutJSON(ctx, "wa:reg:"+userID.String(), sessionData, s.cfg.ChallengeTTL); err != nil {
		return nil, err
	}
	return options, nil
}

func (s *Service) FinishWebAuthnRegister(ctx context.Context, userID uuid.UUID, name string, credentialJSON []byte, ip, ua string) (store.WebAuthnCredential, error) {
	wa, err := s.webAuthn()
	if err != nil {
		return store.WebAuthnCredential{}, err
	}
	var sessionData webauthn.SessionData
	if err := s.sessions.GetJSON(ctx, "wa:reg:"+userID.String(), &sessionData); err != nil {
		return store.WebAuthnCredential{}, fmt.Errorf("registration session expired")
	}
	user, u, err := s.loadWAUser(ctx, userID)
	if err != nil {
		return store.WebAuthnCredential{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(credentialJSON)
	if err != nil {
		return store.WebAuthnCredential{}, fmt.Errorf("invalid credential: %w", err)
	}
	cred, err := wa.CreateCredential(user, sessionData, parsed)
	if err != nil {
		return store.WebAuthnCredential{}, err
	}
	_ = s.sessions.DeleteKey(ctx, "wa:reg:"+userID.String())

	name = strings.TrimSpace(name)
	if name == "" {
		name = "Passkey"
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	saved, err := s.db.InsertWebAuthnCredential(ctx, store.WebAuthnCredential{
		UserID:          userID,
		Name:            name,
		CredentialID:    cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		Transport:       transports,
		SignCount:       cred.Authenticator.SignCount,
		AAGUID:          cred.Authenticator.AAGUID,
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
	})
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			return store.WebAuthnCredential{}, fmt.Errorf("credential already registered")
		}
		return store.WebAuthnCredential{}, err
	}

	if !u.MFAEnabled {
		u.MFAEnabled = true
		u.UpdatedAt = time.Now().UTC()
		if _, err := s.db.UpdateUser(ctx, u, nil); err != nil {
			return store.WebAuthnCredential{}, err
		}
		_ = s.audit.Record(ctx, &userID, "user.mfa.enabled", "user", userID.String(), ip, ua, map[string]any{"method": "webauthn"})
	}
	_ = s.audit.Record(ctx, &userID, "user.webauthn.registered", "user", userID.String(), ip, ua, map[string]any{
		"credential_id": saved.ID.String(),
		"name":          saved.Name,
	})
	return saved, nil
}

func (s *Service) finishWebAuthnAssertion(ctx context.Context, challengeToken string, credentialJSON []byte, ip, ua string, loginAudit bool) (store.User, error) {
	chal, err := s.sessions.GetChallenge(ctx, challengeToken)
	if err != nil {
		return store.User{}, fmt.Errorf("invalid challenge")
	}
	wa, err := s.webAuthn()
	if err != nil {
		return store.User{}, err
	}
	var sessionData webauthn.SessionData
	if err := s.sessions.GetJSON(ctx, "wa:login:"+challengeToken, &sessionData); err != nil {
		return store.User{}, fmt.Errorf("webauthn session expired")
	}
	user, u, err := s.loadWAUser(ctx, chal.UserID)
	if err != nil {
		return store.User{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(credentialJSON)
	if err != nil {
		return store.User{}, fmt.Errorf("invalid assertion")
	}
	cred, err := wa.ValidateLogin(user, sessionData, parsed)
	if err != nil {
		action := "user.login.failure"
		payload := map[string]any{"reason": "invalid_webauthn"}
		if !loginAudit {
			action = "access.stepup.failure"
		}
		_ = s.audit.Record(ctx, &u.ID, action, "user", u.ID.String(), ip, ua, payload)
		return store.User{}, fmt.Errorf("invalid webauthn assertion")
	}
	_ = s.db.UpdateWebAuthnSignCount(ctx, u.ID, cred.ID, cred.Authenticator.SignCount, cred.Flags.BackupState)
	_ = s.sessions.DeleteKey(ctx, "wa:login:"+challengeToken)
	return u, nil
}

func (s *Service) BeginWebAuthnLogin(ctx context.Context, challengeToken string) (any, error) {
	chal, err := s.sessions.GetChallenge(ctx, challengeToken)
	if err != nil {
		return nil, fmt.Errorf("invalid challenge")
	}
	wa, err := s.webAuthn()
	if err != nil {
		return nil, err
	}
	user, _, err := s.loadWAUser(ctx, chal.UserID)
	if err != nil {
		return nil, err
	}
	if len(user.creds) == 0 {
		return nil, fmt.Errorf("no webauthn credentials")
	}
	options, sessionData, err := wa.BeginLogin(user)
	if err != nil {
		return nil, err
	}
	if err := s.sessions.PutJSON(ctx, "wa:login:"+challengeToken, sessionData, s.cfg.ChallengeTTL); err != nil {
		return nil, err
	}
	return options, nil
}

func (s *Service) FinishWebAuthnLogin(ctx context.Context, challengeToken string, credentialJSON []byte, ip, ua string) (LoginResult, error) {
	chal, err := s.sessions.GetChallenge(ctx, challengeToken)
	if err != nil {
		return LoginResult{}, fmt.Errorf("invalid challenge")
	}
	if chal.Purpose == stepUpPurpose {
		return LoginResult{}, fmt.Errorf("invalid challenge")
	}
	u, err := s.finishWebAuthnAssertion(ctx, challengeToken, credentialJSON, ip, ua, true)
	if err != nil {
		return LoginResult{}, err
	}
	_ = s.sessions.DeleteChallenge(ctx, challengeToken)

	sessTok, err := s.issueSession(ctx, u)
	if err != nil {
		return LoginResult{}, err
	}
	now := time.Now().UTC()
	u.LastLoginAt = &now
	u.UpdatedAt = now
	u, _ = s.db.UpdateUser(ctx, u, nil)
	_ = s.audit.Record(ctx, &u.ID, "user.login.success", "user", u.ID.String(), ip, ua, map[string]any{"mfa": true, "method": "webauthn"})
	status := "ok"
	if u.MustChangePassword {
		status = "must_setup"
	}
	return LoginResult{Status: status, SessionToken: sessTok, User: &u}, nil
}

func (s *Service) ListWebAuthnCredentials(ctx context.Context, userID uuid.UUID) ([]store.WebAuthnCredential, error) {
	return s.db.ListWebAuthnCredentials(ctx, userID)
}

func (s *Service) DeleteWebAuthnCredential(ctx context.Context, actorID, userID, credID uuid.UUID, ip, ua string) error {
	if err := s.db.DeleteWebAuthnCredential(ctx, userID, credID); err != nil {
		return err
	}
	_ = s.audit.Record(ctx, &actorID, "user.webauthn.deleted", "user", userID.String(), ip, ua, map[string]any{
		"credential_id": credID.String(),
	})
	n, err := s.db.CountWebAuthnCredentials(ctx, userID)
	if err != nil {
		return err
	}
	u, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if n == 0 && len(u.MFASecretEnc) == 0 && u.MFAEnabled {
		u.MFAEnabled = false
		u.UpdatedAt = time.Now().UTC()
		_, _ = s.db.UpdateUser(ctx, u, nil)
	}
	return nil
}
