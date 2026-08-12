package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/ssh"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/config"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/session"
	"github.com/keeppam/auth/internal/settings"
	"github.com/keeppam/auth/internal/store"
)

type Service struct {
	db       *store.DB
	sessions *session.Store
	audit    *audit.Service
	env      *crypto.Envelope
	cfg      config.Config
	settings *settings.Service
}

func New(db *store.DB, sessions *session.Store, auditSvc *audit.Service, env *crypto.Envelope, cfg config.Config, settingsSvc *settings.Service) *Service {
	return &Service{db: db, sessions: sessions, audit: auditSvc, env: env, cfg: cfg, settings: settingsSvc}
}

type LoginResult struct {
	Status         string `json:"status"` // ok | mfa_required | must_setup
	ChallengeToken string `json:"challenge_token,omitempty"`
	SessionToken   string `json:"-"`
	User           *store.User `json:"user,omitempty"`
}

func (s *Service) Bootstrap(ctx context.Context) error {
	n, err := s.db.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if s.cfg.BootstrapAdminPassword == "" {
		return fmt.Errorf("database empty and KEEPPAM_BOOTSTRAP_ADMIN_PASSWORD not set")
	}
	hash, err := crypto.HashPassword(s.cfg.BootstrapAdminPassword)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	u := store.User{
		ID:                 store.NewID(),
		Username:           "admin",
		Email:              "admin@keeppam.local",
		DisplayName:        "Administrator",
		PasswordHash:       hash,
		Status:             "active",
		AuthSource:         "local",
		MustChangePassword: true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	_, err = s.db.CreateUser(ctx, u, []string{"admin"})
	if err != nil {
		return err
	}
	return s.audit.Record(ctx, &u.ID, "user.created", "user", u.ID.String(), "", "bootstrap", map[string]any{
		"username": "admin",
		"source":   "bootstrap",
	})
}

func (s *Service) Login(ctx context.Context, username, password, ip, ua string) (LoginResult, error) {
	authCfg, oidcSec, ldapSec, err := s.settings.Get(ctx)
	if err != nil {
		return LoginResult{}, err
	}
	_ = oidcSec
	switch authCfg.Mode {
	case "oidc", "saml":
		return LoginResult{}, fmt.Errorf("use SSO login")
	case "ldap":
		return s.loginLDAP(ctx, authCfg, ldapSec, username, password, ip, ua)
	default:
		return s.loginLocal(ctx, username, password, ip, ua)
	}
}

func (s *Service) loginLocal(ctx context.Context, username, password, ip, ua string) (LoginResult, error) {
	rlKey := session.RateKey(ip, username)
	fails, err := s.sessions.IncrLoginFail(ctx, rlKey, s.cfg.LockoutDuration)
	if err != nil {
		return LoginResult{}, err
	}
	if fails > int64(s.cfg.MaxFailedLogins*3) {
		_ = s.audit.Record(ctx, nil, "user.login.failure", "user", username, ip, ua, map[string]any{"reason": "rate_limited"})
		return LoginResult{}, fmt.Errorf("too many attempts")
	}

	u, err := s.db.GetUserByUsername(ctx, username)
	if err != nil {
		_ = s.audit.Record(ctx, nil, "user.login.failure", "user", username, ip, ua, map[string]any{"reason": "invalid_credentials"})
		return LoginResult{}, fmt.Errorf("invalid credentials")
	}
	if u.Status == "disabled" {
		_ = s.audit.Record(ctx, &u.ID, "user.login.failure", "user", u.ID.String(), ip, ua, map[string]any{"reason": "disabled"})
		return LoginResult{}, fmt.Errorf("account disabled")
	}
	if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
		_ = s.audit.Record(ctx, &u.ID, "user.login.failure", "user", u.ID.String(), ip, ua, map[string]any{"reason": "locked"})
		return LoginResult{}, fmt.Errorf("account locked")
	}
	if u.Status == "locked" {
		u.Status = "active"
		u.FailedLoginCount = 0
		u.LockedUntil = nil
		u.UpdatedAt = time.Now().UTC()
		_, _ = s.db.UpdateUser(ctx, u, nil)
	}

	ok, err := crypto.VerifyPassword(u.PasswordHash, password)
	if err != nil || !ok {
		u.FailedLoginCount++
		if u.FailedLoginCount >= s.cfg.MaxFailedLogins {
			until := time.Now().UTC().Add(s.cfg.LockoutDuration)
			u.LockedUntil = &until
			u.Status = "locked"
		}
		u.UpdatedAt = time.Now().UTC()
		_, _ = s.db.UpdateUser(ctx, u, nil)
		_ = s.audit.Record(ctx, &u.ID, "user.login.failure", "user", u.ID.String(), ip, ua, map[string]any{"reason": "invalid_credentials"})
		return LoginResult{}, fmt.Errorf("invalid credentials")
	}

	_ = s.sessions.ResetLoginFail(ctx, rlKey)
	u.FailedLoginCount = 0
	u.LockedUntil = nil
	if u.Status == "locked" {
		u.Status = "active"
	}
	u.UpdatedAt = time.Now().UTC()
	_, _ = s.db.UpdateUser(ctx, u, nil)

	return s.finishLogin(ctx, u, ip, ua, false, "local")
}

func (s *Service) loginLDAP(ctx context.Context, authCfg settings.AuthSettings, ldapSec []byte, username, password, ip, ua string) (LoginResult, error) {
	ident, err := s.settings.AuthenticateLDAP(authCfg, ldapSec, username, password)
	if err != nil {
		_ = s.audit.Record(ctx, nil, "user.login.failure", "user", username, ip, ua, map[string]any{"reason": "ldap", "error": err.Error()})
		return LoginResult{}, fmt.Errorf("invalid credentials")
	}
	u, err := s.findOrProvisionExternal(ctx, ident.Username, ident.Email, ident.DisplayName, "ldap", authCfg.LDAPAutoProvision, authCfg.LDAPDefaultRole)
	if err != nil {
		return LoginResult{}, err
	}
	if u.Status == "disabled" {
		return LoginResult{}, fmt.Errorf("account disabled")
	}
	return s.finishLogin(ctx, u, ip, ua, authCfg.LDAPSkipMFA, "ldap")
}

func (s *Service) LoginOIDC(ctx context.Context, claims settings.OIDCClaims, ip, ua string) (LoginResult, error) {
	authCfg, _, _, err := s.settings.Get(ctx)
	if err != nil {
		return LoginResult{}, err
	}
	if authCfg.Mode != "oidc" {
		return LoginResult{}, fmt.Errorf("oidc is not enabled")
	}
	u, err := s.findOrProvisionExternal(ctx, claims.Username, claims.Email, claims.Name, "oidc", authCfg.OIDCAutoProvision, authCfg.OIDCDefaultRole)
	if err != nil {
		return LoginResult{}, err
	}
	if u.Status == "disabled" {
		return LoginResult{}, fmt.Errorf("account disabled")
	}
	return s.finishLogin(ctx, u, ip, ua, authCfg.OIDCSkipMFA, "oidc")
}

func (s *Service) LoginSAML(ctx context.Context, claims settings.SAMLClaims, ip, ua string) (LoginResult, error) {
	authCfg, _, _, err := s.settings.Get(ctx)
	if err != nil {
		return LoginResult{}, err
	}
	if authCfg.Mode != "saml" {
		return LoginResult{}, fmt.Errorf("saml is not enabled")
	}
	u, err := s.findOrProvisionExternal(ctx, claims.Username, claims.Email, claims.Name, "saml", authCfg.SAMLAutoProvision, authCfg.SAMLDefaultRole)
	if err != nil {
		return LoginResult{}, err
	}
	if u.Status == "disabled" {
		return LoginResult{}, fmt.Errorf("account disabled")
	}
	return s.finishLogin(ctx, u, ip, ua, authCfg.SAMLSkipMFA, "saml")
}

func (s *Service) findOrProvisionExternal(ctx context.Context, username, email, displayName, source string, autoProvision bool, defaultRole string) (store.User, error) {
	u, err := s.db.GetUserByUsername(ctx, username)
	if err == nil {
		return u, nil
	}
	if email != "" {
		if u2, err2 := s.db.GetUserByEmail(ctx, email); err2 == nil {
			return u2, nil
		}
	}
	if !autoProvision {
		return store.User{}, fmt.Errorf("user not provisioned")
	}
	if defaultRole == "" {
		defaultRole = "operator"
	}
	// Unusable random password hash for external accounts.
	hash, err := crypto.HashPassword(uuid.NewString() + uuid.NewString())
	if err != nil {
		return store.User{}, err
	}
	now := time.Now().UTC()
	u = store.User{
		ID:                 store.NewID(),
		Username:           username,
		Email:              email,
		DisplayName:        displayName,
		PasswordHash:       hash,
		Status:             "active",
		AuthSource:         source,
		MustChangePassword: false,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	created, err := s.db.CreateUser(ctx, u, []string{defaultRole})
	if err != nil {
		return store.User{}, err
	}
	_ = s.audit.Record(ctx, &created.ID, "user.created", "user", created.ID.String(), "", source, map[string]any{
		"username": username, "source": source, "auto_provision": true,
	})
	return created, nil
}

func (s *Service) finishLogin(ctx context.Context, u store.User, ip, ua string, skipMFA bool, via string) (LoginResult, error) {
	if u.MFAEnabled && !skipMFA {
		tok, err := s.sessions.CreateChallenge(ctx, session.Challenge{UserID: u.ID, Username: u.Username}, s.cfg.ChallengeTTL)
		if err != nil {
			return LoginResult{}, err
		}
		return LoginResult{Status: "mfa_required", ChallengeToken: tok}, nil
	}

	sessTok, err := s.issueSession(ctx, u)
	if err != nil {
		return LoginResult{}, err
	}
	now := time.Now().UTC()
	u.LastLoginAt = &now
	u.UpdatedAt = now
	u, _ = s.db.UpdateUser(ctx, u, nil)
	_ = s.audit.Record(ctx, &u.ID, "user.login.success", "user", u.ID.String(), ip, ua, map[string]any{"mfa": false, "via": via})
	status := "ok"
	if u.MustChangePassword {
		status = "must_setup"
	} else if !skipMFA && !u.MFAEnabled {
		status = "must_setup"
	}
	return LoginResult{Status: status, SessionToken: sessTok, User: &u}, nil
}

func (s *Service) VerifyMFA(ctx context.Context, challengeToken, code, ip, ua string) (LoginResult, error) {
	chal, err := s.sessions.GetChallenge(ctx, challengeToken)
	if err != nil {
		return LoginResult{}, fmt.Errorf("invalid challenge")
	}
	u, err := s.db.GetUserByID(ctx, chal.UserID)
	if err != nil {
		return LoginResult{}, err
	}
	if len(u.MFASecretEnc) == 0 {
		return LoginResult{}, fmt.Errorf("totp not configured")
	}
	secret, err := s.env.Decrypt(u.MFASecretEnc)
	if err != nil {
		return LoginResult{}, err
	}
	if !totp.Validate(code, string(secret)) {
		_ = s.audit.Record(ctx, &u.ID, "user.login.failure", "user", u.ID.String(), ip, ua, map[string]any{"reason": "invalid_mfa"})
		return LoginResult{}, fmt.Errorf("invalid mfa code")
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
	_ = s.audit.Record(ctx, &u.ID, "user.login.success", "user", u.ID.String(), ip, ua, map[string]any{"mfa": true, "method": "totp"})
	status := "ok"
	if u.MustChangePassword {
		status = "must_setup"
	}
	return LoginResult{Status: status, SessionToken: sessTok, User: &u}, nil
}

func (s *Service) issueSession(ctx context.Context, u store.User) (string, error) {
	return s.sessions.Create(ctx, session.Session{
		UserID: u.ID, Username: u.Username, Roles: u.Roles, Permissions: u.Permissions,
	}, s.cfg.SessionTTL)
}

func (s *Service) Logout(ctx context.Context, token string, actorID *uuid.UUID, ip, ua string) error {
	_ = s.sessions.Delete(ctx, token)
	return s.audit.Record(ctx, actorID, "user.logout", "user", "", ip, ua, nil)
}

func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, current, newPassword string) error {
	u, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if current != "" {
		ok, err := crypto.VerifyPassword(u.PasswordHash, current)
		if err != nil || !ok {
			return fmt.Errorf("current password incorrect")
		}
	}
	if len(newPassword) < 10 {
		return fmt.Errorf("password too short")
	}
	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	u.MustChangePassword = false
	u.UpdatedAt = time.Now().UTC()
	_, err = s.db.UpdateUser(ctx, u, nil)
	return err
}

type MFASetup struct {
	Secret string `json:"secret"`
	URL    string `json:"url"`
}

func (s *Service) BeginMFASetup(ctx context.Context, userID uuid.UUID) (MFASetup, error) {
	u, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return MFASetup{}, err
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "KeepPAM",
		AccountName: u.Username,
	})
	if err != nil {
		return MFASetup{}, err
	}
	enc, err := s.env.Encrypt([]byte(key.Secret()))
	if err != nil {
		return MFASetup{}, err
	}
	u.MFASecretEnc = enc
	u.MFAEnabled = false
	u.UpdatedAt = time.Now().UTC()
	_, err = s.db.UpdateUser(ctx, u, nil)
	if err != nil {
		return MFASetup{}, err
	}
	return MFASetup{Secret: key.Secret(), URL: key.URL()}, nil
}

func (s *Service) ConfirmMFASetup(ctx context.Context, userID uuid.UUID, code, ip, ua string) error {
	u, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if len(u.MFASecretEnc) == 0 {
		return fmt.Errorf("mfa setup not started")
	}
	secret, err := s.env.Decrypt(u.MFASecretEnc)
	if err != nil {
		return err
	}
	if !totp.Validate(code, string(secret)) {
		return fmt.Errorf("invalid mfa code")
	}
	u.MFAEnabled = true
	u.UpdatedAt = time.Now().UTC()
	_, err = s.db.UpdateUser(ctx, u, nil)
	if err != nil {
		return err
	}
	return s.audit.Record(ctx, &userID, "user.mfa.enabled", "user", userID.String(), ip, ua, nil)
}

func (s *Service) Me(ctx context.Context, userID uuid.UUID) (store.User, error) {
	return s.db.GetUserByID(ctx, userID)
}

func (s *Service) AuthenticatePassword(ctx context.Context, username, password, ip string) (store.User, error) {
	authCfg, _, ldapSec, err := s.settings.Get(ctx)
	if err != nil {
		return store.User{}, err
	}
	if authCfg.Mode == "ldap" {
		ident, err := s.settings.AuthenticateLDAP(authCfg, ldapSec, username, password)
		if err != nil {
			_ = s.audit.Record(ctx, nil, "user.login.failure", "user", username, ip, "ssh", map[string]any{"reason": "ldap"})
			return store.User{}, fmt.Errorf("invalid credentials")
		}
		u, err := s.findOrProvisionExternal(ctx, ident.Username, ident.Email, ident.DisplayName, "ldap", authCfg.LDAPAutoProvision, authCfg.LDAPDefaultRole)
		if err != nil {
			return store.User{}, err
		}
		if u.Status == "disabled" {
			return store.User{}, fmt.Errorf("account disabled")
		}
		return u, nil
	}
	// local (and oidc mode): local password hash for SSH
	return s.authenticateLocalPassword(ctx, username, password, ip)
}

func (s *Service) authenticateLocalPassword(ctx context.Context, username, password, ip string) (store.User, error) {
	rlKey := session.RateKey(ip, username)
	fails, err := s.sessions.IncrLoginFail(ctx, rlKey, s.cfg.LockoutDuration)
	if err != nil {
		return store.User{}, err
	}
	if fails > int64(s.cfg.MaxFailedLogins*3) {
		_ = s.audit.Record(ctx, nil, "user.login.failure", "user", username, ip, "ssh", map[string]any{"reason": "rate_limited"})
		return store.User{}, fmt.Errorf("too many attempts")
	}

	u, err := s.db.GetUserByUsername(ctx, username)
	if err != nil {
		_ = s.audit.Record(ctx, nil, "user.login.failure", "user", username, ip, "ssh", map[string]any{"reason": "invalid_credentials"})
		return store.User{}, fmt.Errorf("invalid credentials")
	}
	if u.Status == "disabled" {
		return store.User{}, fmt.Errorf("account disabled")
	}
	if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
		return store.User{}, fmt.Errorf("account locked")
	}
	if u.Status == "locked" {
		u.Status = "active"
		u.FailedLoginCount = 0
		u.LockedUntil = nil
		u.UpdatedAt = time.Now().UTC()
		_, _ = s.db.UpdateUser(ctx, u, nil)
	}

	ok, err := crypto.VerifyPassword(u.PasswordHash, password)
	if err != nil || !ok {
		u.FailedLoginCount++
		if u.FailedLoginCount >= s.cfg.MaxFailedLogins {
			until := time.Now().UTC().Add(s.cfg.LockoutDuration)
			u.LockedUntil = &until
			u.Status = "locked"
		}
		u.UpdatedAt = time.Now().UTC()
		_, _ = s.db.UpdateUser(ctx, u, nil)
		_ = s.audit.Record(ctx, &u.ID, "user.login.failure", "user", u.ID.String(), ip, "ssh", map[string]any{"reason": "invalid_credentials"})
		return store.User{}, fmt.Errorf("invalid credentials")
	}

	_ = s.sessions.ResetLoginFail(ctx, rlKey)
	u.FailedLoginCount = 0
	u.LockedUntil = nil
	if u.Status == "locked" {
		u.Status = "active"
	}
	u.UpdatedAt = time.Now().UTC()
	u, _ = s.db.UpdateUser(ctx, u, nil)
	return u, nil
}

func (s *Service) ValidateTOTP(ctx context.Context, userID uuid.UUID, code, ip string) error {
	u, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !u.MFAEnabled || len(u.MFASecretEnc) == 0 {
		return nil
	}
	secret, err := s.env.Decrypt(u.MFASecretEnc)
	if err != nil {
		return err
	}
	if !totp.Validate(code, string(secret)) {
		_ = s.audit.Record(ctx, &userID, "user.login.failure", "user", userID.String(), ip, "ssh", map[string]any{"reason": "invalid_mfa"})
		return fmt.Errorf("invalid mfa code")
	}
	now := time.Now().UTC()
	u.LastLoginAt = &now
	u.UpdatedAt = now
	_, _ = s.db.UpdateUser(ctx, u, nil)
	_ = s.audit.Record(ctx, &userID, "user.login.success", "user", userID.String(), ip, "ssh", map[string]any{"mfa": true, "via": "ssh"})
	return nil
}

// AuthenticatePublicKey verifies an enrolled SSH public key for the given PAM username.
func (s *Service) AuthenticatePublicKey(ctx context.Context, username string, key ssh.PublicKey, ip string) (store.User, error) {
	fp := ssh.FingerprintSHA256(key)
	var userID uuid.UUID
	err := s.db.Pool.QueryRow(ctx, `
		SELECT u.id FROM user_ssh_keys k
		JOIN users u ON u.id = k.user_id
		WHERE k.fingerprint=$1 AND lower(u.username)=lower($2)`, fp, username).Scan(&userID)
	if err != nil {
		_ = s.audit.Record(ctx, nil, "user.login.failure", "user", username, ip, "ssh", map[string]any{"reason": "invalid_pubkey"})
		return store.User{}, fmt.Errorf("invalid credentials")
	}
	u, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return store.User{}, err
	}
	if u.Status == "disabled" {
		return store.User{}, fmt.Errorf("account disabled")
	}
	if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
		return store.User{}, fmt.Errorf("account locked")
	}
	if u.Status == "locked" {
		u.Status = "active"
		u.FailedLoginCount = 0
		u.LockedUntil = nil
		u.UpdatedAt = time.Now().UTC()
		_, _ = s.db.UpdateUser(ctx, u, nil)
	}
	return u, nil
}

func IsNotFound(err error) bool {
	return err == pgx.ErrNoRows
}
