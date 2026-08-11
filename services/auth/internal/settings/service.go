package settings

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/store"
)

type AuthSettings struct {
	Mode          string `json:"mode"`
	PublicBaseURL string `json:"public_base_url"`

	OIDCIssuer         string `json:"oidc_issuer"`
	OIDCClientID       string `json:"oidc_client_id"`
	OIDCClientSecret   string `json:"oidc_client_secret,omitempty"` // write-only; never returned filled from DB
	HasOIDCSecret      bool   `json:"has_oidc_secret"`
	OIDCScopes         string `json:"oidc_scopes"`
	OIDCAutoProvision  bool   `json:"oidc_auto_provision"`
	OIDCSkipMFA        bool   `json:"oidc_skip_mfa"`
	OIDCDefaultRole    string `json:"oidc_default_role"`

	LDAPURL              string `json:"ldap_url"`
	LDAPBindDN           string `json:"ldap_bind_dn"`
	LDAPBindPassword     string `json:"ldap_bind_password,omitempty"`
	HasLDAPBindPassword  bool   `json:"has_ldap_bind_password"`
	LDAPUserBaseDN       string `json:"ldap_user_base_dn"`
	LDAPUserFilter       string `json:"ldap_user_filter"`
	LDAPAttrUsername     string `json:"ldap_attr_username"`
	LDAPAttrEmail        string `json:"ldap_attr_email"`
	LDAPAttrDisplayName  string `json:"ldap_attr_display_name"`
	LDAPStartTLS         bool   `json:"ldap_start_tls"`
	LDAPInsecureTLS      bool   `json:"ldap_insecure_tls"`
	LDAPAutoProvision    bool   `json:"ldap_auto_provision"`
	LDAPSkipMFA          bool   `json:"ldap_skip_mfa"`
	LDAPDefaultRole      string `json:"ldap_default_role"`

	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

type PublicAuthMethods struct {
	Mode      string `json:"mode"`
	OIDCReady bool   `json:"oidc_ready"`
	LDAPReady bool   `json:"ldap_ready"`
}

type Service struct {
	db  *store.DB
	aud *audit.Service
	env *crypto.Envelope
}

func New(db *store.DB, aud *audit.Service, env *crypto.Envelope) *Service {
	return &Service{db: db, aud: aud, env: env}
}

func (s *Service) Get(ctx context.Context) (AuthSettings, []byte, []byte, error) {
	var out AuthSettings
	var oidcSec, ldapSec []byte
	var updatedAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT mode, public_base_url,
			oidc_issuer, oidc_client_id, oidc_client_secret_enc, oidc_scopes,
			oidc_auto_provision, oidc_skip_mfa, oidc_default_role,
			ldap_url, ldap_bind_dn, ldap_bind_password_enc, ldap_user_base_dn, ldap_user_filter,
			ldap_attr_username, ldap_attr_email, ldap_attr_display_name,
			ldap_start_tls, ldap_insecure_tls, ldap_auto_provision, ldap_skip_mfa, ldap_default_role,
			updated_at
		FROM auth_settings WHERE id=1`).Scan(
		&out.Mode, &out.PublicBaseURL,
		&out.OIDCIssuer, &out.OIDCClientID, &oidcSec, &out.OIDCScopes,
		&out.OIDCAutoProvision, &out.OIDCSkipMFA, &out.OIDCDefaultRole,
		&out.LDAPURL, &out.LDAPBindDN, &ldapSec, &out.LDAPUserBaseDN, &out.LDAPUserFilter,
		&out.LDAPAttrUsername, &out.LDAPAttrEmail, &out.LDAPAttrDisplayName,
		&out.LDAPStartTLS, &out.LDAPInsecureTLS, &out.LDAPAutoProvision, &out.LDAPSkipMFA, &out.LDAPDefaultRole,
		&updatedAt,
	)
	if err != nil {
		return out, nil, nil, err
	}
	out.HasOIDCSecret = len(oidcSec) > 0
	out.HasLDAPBindPassword = len(ldapSec) > 0
	out.UpdatedAt = &updatedAt
	return out, oidcSec, ldapSec, nil
}

func (s *Service) PublicMethods(ctx context.Context) (PublicAuthMethods, error) {
	cfg, oidcSec, ldapSec, err := s.Get(ctx)
	if err != nil {
		return PublicAuthMethods{}, err
	}
	ldapReady := cfg.Mode == "ldap" && cfg.LDAPURL != "" && cfg.LDAPUserBaseDN != ""
	_ = ldapSec
	return PublicAuthMethods{
		Mode:      cfg.Mode,
		OIDCReady: cfg.Mode == "oidc" && cfg.OIDCIssuer != "" && cfg.OIDCClientID != "" && len(oidcSec) > 0,
		LDAPReady: ldapReady,
	}, nil
}

func (s *Service) Update(ctx context.Context, actorID uuid.UUID, in AuthSettings, ip, ua string) (AuthSettings, error) {
	mode := strings.TrimSpace(in.Mode)
	if mode != "local" && mode != "oidc" && mode != "ldap" {
		return AuthSettings{}, fmt.Errorf("mode must be local|oidc|ldap")
	}
	cur, oidcSec, ldapSec, err := s.Get(ctx)
	if err != nil {
		return AuthSettings{}, err
	}
	if strings.TrimSpace(in.OIDCClientSecret) != "" {
		enc, err := s.env.Encrypt([]byte(in.OIDCClientSecret))
		if err != nil {
			return AuthSettings{}, err
		}
		oidcSec = enc
	}
	if strings.TrimSpace(in.LDAPBindPassword) != "" {
		enc, err := s.env.Encrypt([]byte(in.LDAPBindPassword))
		if err != nil {
			return AuthSettings{}, err
		}
		ldapSec = enc
	}
	if in.OIDCScopes == "" {
		in.OIDCScopes = "openid profile email"
	}
	if in.OIDCDefaultRole == "" {
		in.OIDCDefaultRole = "operator"
	}
	if in.LDAPUserFilter == "" {
		in.LDAPUserFilter = "(uid=%s)"
	}
	if in.LDAPAttrUsername == "" {
		in.LDAPAttrUsername = "uid"
	}
	if in.LDAPAttrEmail == "" {
		in.LDAPAttrEmail = "mail"
	}
	if in.LDAPAttrDisplayName == "" {
		in.LDAPAttrDisplayName = "cn"
	}
	if in.LDAPDefaultRole == "" {
		in.LDAPDefaultRole = "operator"
	}
	publicURL := strings.TrimRight(strings.TrimSpace(in.PublicBaseURL), "/")
	if publicURL == "" {
		publicURL = cur.PublicBaseURL
	}

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE auth_settings SET
			mode=$2, public_base_url=$3,
			oidc_issuer=$4, oidc_client_id=$5, oidc_client_secret_enc=$6, oidc_scopes=$7,
			oidc_auto_provision=$8, oidc_skip_mfa=$9, oidc_default_role=$10,
			ldap_url=$11, ldap_bind_dn=$12, ldap_bind_password_enc=$13, ldap_user_base_dn=$14, ldap_user_filter=$15,
			ldap_attr_username=$16, ldap_attr_email=$17, ldap_attr_display_name=$18,
			ldap_start_tls=$19, ldap_insecure_tls=$20, ldap_auto_provision=$21, ldap_skip_mfa=$22, ldap_default_role=$23,
			updated_at=NOW(), updated_by=$24
		WHERE id=1`,
		1, mode, publicURL,
		strings.TrimSpace(in.OIDCIssuer), strings.TrimSpace(in.OIDCClientID), oidcSec, strings.TrimSpace(in.OIDCScopes),
		in.OIDCAutoProvision, in.OIDCSkipMFA, strings.TrimSpace(in.OIDCDefaultRole),
		strings.TrimSpace(in.LDAPURL), strings.TrimSpace(in.LDAPBindDN), ldapSec, strings.TrimSpace(in.LDAPUserBaseDN), strings.TrimSpace(in.LDAPUserFilter),
		strings.TrimSpace(in.LDAPAttrUsername), strings.TrimSpace(in.LDAPAttrEmail), strings.TrimSpace(in.LDAPAttrDisplayName),
		in.LDAPStartTLS, in.LDAPInsecureTLS, in.LDAPAutoProvision, in.LDAPSkipMFA, strings.TrimSpace(in.LDAPDefaultRole),
		actorID,
	)
	if err != nil {
		return AuthSettings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "settings.auth.updated", "settings", "auth", ip, ua, map[string]any{"mode": mode})
	out, _, _, err := s.Get(ctx)
	return out, err
}

func (s *Service) DecryptSecret(enc []byte) (string, error) {
	if len(enc) == 0 {
		return "", nil
	}
	b, err := s.env.Decrypt(enc)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func IsNotFound(err error) bool { return err == pgx.ErrNoRows }
