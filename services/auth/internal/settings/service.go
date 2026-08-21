package settings

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
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

	OIDCIssuer        string `json:"oidc_issuer"`
	OIDCClientID      string `json:"oidc_client_id"`
	OIDCClientSecret  string `json:"oidc_client_secret,omitempty"` // write-only; never returned filled from DB
	HasOIDCSecret     bool   `json:"has_oidc_secret"`
	OIDCScopes        string `json:"oidc_scopes"`
	OIDCAutoProvision bool   `json:"oidc_auto_provision"`
	OIDCSkipMFA       bool   `json:"oidc_skip_mfa"`
	OIDCDefaultRole   string `json:"oidc_default_role"`

	LDAPURL             string `json:"ldap_url"`
	LDAPBindDN          string `json:"ldap_bind_dn"`
	LDAPBindPassword    string `json:"ldap_bind_password,omitempty"`
	HasLDAPBindPassword bool   `json:"has_ldap_bind_password"`
	LDAPUserBaseDN      string `json:"ldap_user_base_dn"`
	LDAPUserFilter      string `json:"ldap_user_filter"`
	LDAPAttrUsername    string `json:"ldap_attr_username"`
	LDAPAttrEmail       string `json:"ldap_attr_email"`
	LDAPAttrDisplayName string `json:"ldap_attr_display_name"`
	LDAPStartTLS        bool   `json:"ldap_start_tls"`
	LDAPInsecureTLS     bool   `json:"ldap_insecure_tls"`
	LDAPAutoProvision   bool   `json:"ldap_auto_provision"`
	LDAPSkipMFA         bool   `json:"ldap_skip_mfa"`
	LDAPDefaultRole     string `json:"ldap_default_role"`

	RADIUSHost          string `json:"radius_host"`
	RADIUSNASID         string `json:"radius_nas_id"`
	RADIUSTimeoutSec    int    `json:"radius_timeout_sec"`
	RADIUSSecret        string `json:"radius_secret,omitempty"`
	HasRADIUSSecret     bool   `json:"has_radius_secret"`
	RADIUSAutoProvision bool   `json:"radius_auto_provision"`
	RADIUSSkipMFA       bool   `json:"radius_skip_mfa"`
	RADIUSDefaultRole   string `json:"radius_default_role"`

	SAMLIdPMetadataURL  string            `json:"saml_idp_metadata_url"`
	SAMLIdPEntityID     string            `json:"saml_idp_entity_id"`
	SAMLIdPSSOURL       string            `json:"saml_idp_sso_url"`
	SAMLIdPCertPEM      string            `json:"saml_idp_cert_pem"`
	SAMLSPEntityID      string            `json:"saml_sp_entity_id"`
	HasSAMLSPKey        bool              `json:"has_saml_sp_key"`
	RotateSAMLSPKey     bool              `json:"rotate_saml_sp_key,omitempty"`
	SAMLAttrUsername    string            `json:"saml_attr_username"`
	SAMLAttrEmail       string            `json:"saml_attr_email"`
	SAMLAttrDisplayName string            `json:"saml_attr_display_name"`
	SAMLAutoProvision   bool              `json:"saml_auto_provision"`
	SAMLSkipMFA         bool              `json:"saml_skip_mfa"`
	SAMLDefaultRole     string            `json:"saml_default_role"`
	SAMLGroupAttr       string            `json:"saml_group_attr"`
	SAMLGroupRoleMap    map[string]string `json:"saml_group_role_map"`
	SAMLACSURL          string            `json:"saml_acs_url,omitempty"`
	SAMLMetadataURL     string            `json:"saml_metadata_url,omitempty"`
	SAMLSLOURL          string            `json:"saml_slo_url,omitempty"`

	SCIMEnabled     bool   `json:"scim_enabled"`
	SCIMToken       string `json:"scim_token,omitempty"` // write-only; never returned filled from DB
	HasSCIMToken    bool   `json:"has_scim_token"`
	SCIMDefaultRole string `json:"scim_default_role"`
	SCIMBaseURL     string `json:"scim_base_url,omitempty"`

	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

type PublicAuthMethods struct {
	Mode        string          `json:"mode"`
	OIDCReady   bool            `json:"oidc_ready"`
	LDAPReady   bool            `json:"ldap_ready"`
	SAMLReady   bool            `json:"saml_ready"`
	SAMLIdPs    []PublicSAMLIdP `json:"saml_idps"`
	RADIUSReady bool            `json:"radius_ready"`
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
	var oidcSec, ldapSec, samlKey, scimEnc, radiusSec []byte
	var updatedAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT mode, public_base_url,
			oidc_issuer, oidc_client_id, oidc_client_secret_enc, oidc_scopes,
			oidc_auto_provision, oidc_skip_mfa, oidc_default_role,
			ldap_url, ldap_bind_dn, ldap_bind_password_enc, ldap_user_base_dn, ldap_user_filter,
			ldap_attr_username, ldap_attr_email, ldap_attr_display_name,
			ldap_start_tls, ldap_insecure_tls, ldap_auto_provision, ldap_skip_mfa, ldap_default_role,
			saml_idp_metadata_url, saml_idp_entity_id, saml_idp_sso_url, saml_idp_cert_pem,
			saml_sp_entity_id, saml_sp_key_enc,
			saml_attr_username, saml_attr_email, saml_attr_display_name,
			saml_auto_provision, saml_skip_mfa, saml_default_role,
			COALESCE(saml_group_attr,'groups'), COALESCE(saml_group_role_map,'{}'::jsonb),
			COALESCE(scim_enabled, FALSE), scim_token_enc, COALESCE(scim_default_role, 'operator'),
			COALESCE(radius_host,''), COALESCE(radius_nas_id,'keeppam'), COALESCE(radius_timeout_sec,5),
			radius_secret_enc,
			COALESCE(radius_auto_provision, TRUE), COALESCE(radius_skip_mfa, FALSE), COALESCE(radius_default_role, 'operator'),
			updated_at
		FROM auth_settings WHERE id=1`).Scan(
		&out.Mode, &out.PublicBaseURL,
		&out.OIDCIssuer, &out.OIDCClientID, &oidcSec, &out.OIDCScopes,
		&out.OIDCAutoProvision, &out.OIDCSkipMFA, &out.OIDCDefaultRole,
		&out.LDAPURL, &out.LDAPBindDN, &ldapSec, &out.LDAPUserBaseDN, &out.LDAPUserFilter,
		&out.LDAPAttrUsername, &out.LDAPAttrEmail, &out.LDAPAttrDisplayName,
		&out.LDAPStartTLS, &out.LDAPInsecureTLS, &out.LDAPAutoProvision, &out.LDAPSkipMFA, &out.LDAPDefaultRole,
		&out.SAMLIdPMetadataURL, &out.SAMLIdPEntityID, &out.SAMLIdPSSOURL, &out.SAMLIdPCertPEM,
		&out.SAMLSPEntityID, &samlKey,
		&out.SAMLAttrUsername, &out.SAMLAttrEmail, &out.SAMLAttrDisplayName,
		&out.SAMLAutoProvision, &out.SAMLSkipMFA, &out.SAMLDefaultRole,
		&out.SAMLGroupAttr, &out.SAMLGroupRoleMap,
		&out.SCIMEnabled, &scimEnc, &out.SCIMDefaultRole,
		&out.RADIUSHost, &out.RADIUSNASID, &out.RADIUSTimeoutSec, &radiusSec,
		&out.RADIUSAutoProvision, &out.RADIUSSkipMFA, &out.RADIUSDefaultRole,
		&updatedAt,
	)
	if err != nil {
		return out, nil, nil, err
	}
	out.HasOIDCSecret = len(oidcSec) > 0
	out.HasLDAPBindPassword = len(ldapSec) > 0
	out.HasSAMLSPKey = len(samlKey) > 0
	out.HasSCIMToken = len(scimEnc) > 0
	out.HasRADIUSSecret = len(radiusSec) > 0
	out.UpdatedAt = &updatedAt
	if out.SAMLGroupRoleMap == nil {
		out.SAMLGroupRoleMap = map[string]string{}
	}
	s.fillSAMLDerived(&out)
	s.fillSCIMDerived(&out)
	return out, oidcSec, ldapSec, nil
}

func (s *Service) GetSAMLSPKeyEnc(ctx context.Context) ([]byte, error) {
	var enc []byte
	err := s.db.Pool.QueryRow(ctx, `SELECT saml_sp_key_enc FROM auth_settings WHERE id=1`).Scan(&enc)
	return enc, err
}

func (s *Service) scimTokenEnc(ctx context.Context) ([]byte, error) {
	var enc []byte
	err := s.db.Pool.QueryRow(ctx, `SELECT scim_token_enc FROM auth_settings WHERE id=1`).Scan(&enc)
	return enc, err
}

func (s *Service) RADIUSSecretEnc(ctx context.Context) ([]byte, error) {
	var enc []byte
	err := s.db.Pool.QueryRow(ctx, `SELECT radius_secret_enc FROM auth_settings WHERE id=1`).Scan(&enc)
	return enc, err
}

func (s *Service) fillSCIMDerived(out *AuthSettings) {
	base := strings.TrimRight(out.PublicBaseURL, "/")
	if base != "" {
		out.SCIMBaseURL = base + "/scim/v2"
	}
	out.SCIMDefaultRole = clampSCIMRole(out.SCIMDefaultRole)
}

type SCIMRuntime struct {
	Enabled     bool
	Token       string
	DefaultRole string
}

func (s *Service) SCIMRuntime(ctx context.Context) (SCIMRuntime, error) {
	var enabled bool
	var enc []byte
	var role string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(scim_enabled, FALSE), scim_token_enc, COALESCE(scim_default_role, 'operator')
		FROM auth_settings WHERE id=1`).Scan(&enabled, &enc, &role)
	if err != nil {
		return SCIMRuntime{}, err
	}
	token, err := s.DecryptSecret(enc)
	if err != nil {
		return SCIMRuntime{}, err
	}
	return SCIMRuntime{Enabled: enabled, Token: token, DefaultRole: clampSCIMRole(role)}, nil
}

func clampSCIMRole(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" || role == "admin" {
		return "operator"
	}
	return role
}

func (s *Service) fillSAMLDerived(out *AuthSettings) {
	base := strings.TrimRight(out.PublicBaseURL, "/")
	if base != "" {
		out.SAMLACSURL = base + "/api/v1/auth/saml/acs"
		out.SAMLMetadataURL = base + "/api/v1/auth/saml/metadata"
		out.SAMLSLOURL = base + "/api/v1/auth/saml/slo"
		if out.SAMLSPEntityID == "" {
			out.SAMLSPEntityID = out.SAMLMetadataURL
		}
	}
}

func (s *Service) PublicMethods(ctx context.Context) (PublicAuthMethods, error) {
	cfg, oidcSec, ldapSec, err := s.Get(ctx)
	if err != nil {
		return PublicAuthMethods{}, err
	}
	_ = ldapSec
	idps := s.PublicSAMLIdPs(ctx, cfg)
	return PublicAuthMethods{
		Mode:        cfg.Mode,
		OIDCReady:   cfg.Mode == "oidc" && cfg.OIDCIssuer != "" && cfg.OIDCClientID != "" && len(oidcSec) > 0,
		LDAPReady:   cfg.Mode == "ldap" && cfg.LDAPURL != "" && cfg.LDAPUserBaseDN != "",
		SAMLReady:   cfg.Mode == "saml" && cfg.HasSAMLSPKey && len(idps) > 0,
		SAMLIdPs:    idps,
		RADIUSReady: RADIUSReady(cfg),
	}, nil
}

func SAMLConfigured(cfg AuthSettings) bool {
	if cfg.PublicBaseURL == "" || !cfg.HasSAMLSPKey {
		return false
	}
	if strings.TrimSpace(cfg.SAMLIdPMetadataURL) != "" {
		return true
	}
	return strings.TrimSpace(cfg.SAMLIdPEntityID) != "" &&
		strings.TrimSpace(cfg.SAMLIdPSSOURL) != "" &&
		strings.TrimSpace(cfg.SAMLIdPCertPEM) != ""
}

func (s *Service) Update(ctx context.Context, actorID uuid.UUID, in AuthSettings, ip, ua string) (AuthSettings, error) {
	mode := strings.TrimSpace(in.Mode)
	if mode != "local" && mode != "oidc" && mode != "ldap" && mode != "saml" && mode != "radius" {
		return AuthSettings{}, fmt.Errorf("mode must be local|oidc|ldap|saml|radius")
	}
	cur, oidcSec, ldapSec, err := s.Get(ctx)
	if err != nil {
		return AuthSettings{}, err
	}
	samlKeyEnc, err := s.GetSAMLSPKeyEnc(ctx)
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
	radiusSec, err := s.RADIUSSecretEnc(ctx)
	if err != nil {
		return AuthSettings{}, err
	}
	if strings.TrimSpace(in.RADIUSSecret) != "" {
		enc, err := s.env.Encrypt([]byte(strings.TrimSpace(in.RADIUSSecret)))
		if err != nil {
			return AuthSettings{}, err
		}
		radiusSec = enc
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
	if in.RADIUSNASID == "" {
		in.RADIUSNASID = "keeppam"
	}
	if in.RADIUSTimeoutSec < 1 || in.RADIUSTimeoutSec > 30 {
		in.RADIUSTimeoutSec = 5
	}
	if in.RADIUSDefaultRole == "" {
		in.RADIUSDefaultRole = "operator"
	}
	if mode == "radius" {
		if strings.TrimSpace(in.RADIUSHost) == "" {
			return AuthSettings{}, fmt.Errorf("radius_host required")
		}
		if len(radiusSec) == 0 {
			return AuthSettings{}, fmt.Errorf("radius_secret required")
		}
	}
	if in.SAMLAttrUsername == "" {
		in.SAMLAttrUsername = "uid"
	}
	if in.SAMLAttrEmail == "" {
		in.SAMLAttrEmail = "email"
	}
	if in.SAMLAttrDisplayName == "" {
		in.SAMLAttrDisplayName = "displayName"
	}
	if in.SAMLDefaultRole == "" {
		in.SAMLDefaultRole = "operator"
	}
	if in.SAMLGroupAttr == "" {
		in.SAMLGroupAttr = "groups"
	}
	if in.SAMLGroupRoleMap == nil {
		in.SAMLGroupRoleMap = map[string]string{}
	}
	in.SCIMDefaultRole = clampSCIMRole(in.SCIMDefaultRole)
	scimEnc, err := s.scimTokenEnc(ctx)
	if err != nil {
		return AuthSettings{}, err
	}
	if strings.TrimSpace(in.SCIMToken) != "" {
		enc, err := s.env.Encrypt([]byte(strings.TrimSpace(in.SCIMToken)))
		if err != nil {
			return AuthSettings{}, err
		}
		scimEnc = enc
	}
	publicURL := strings.TrimRight(strings.TrimSpace(in.PublicBaseURL), "/")
	if publicURL == "" {
		publicURL = cur.PublicBaseURL
	}
	spEntity := strings.TrimSpace(in.SAMLSPEntityID)
	if spEntity == "" && publicURL != "" {
		spEntity = publicURL + "/api/v1/auth/saml/metadata"
	}

	if mode == "saml" && (len(samlKeyEnc) == 0 || in.RotateSAMLSPKey) {
		pemBlob, err := generateSAMLSPKeyPEM(spEntity)
		if err != nil {
			return AuthSettings{}, err
		}
		enc, err := s.env.Encrypt(pemBlob)
		if err != nil {
			return AuthSettings{}, err
		}
		samlKeyEnc = enc
	}

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE auth_settings SET
			mode=$2, public_base_url=$3,
			oidc_issuer=$4, oidc_client_id=$5, oidc_client_secret_enc=$6, oidc_scopes=$7,
			oidc_auto_provision=$8, oidc_skip_mfa=$9, oidc_default_role=$10,
			ldap_url=$11, ldap_bind_dn=$12, ldap_bind_password_enc=$13, ldap_user_base_dn=$14, ldap_user_filter=$15,
			ldap_attr_username=$16, ldap_attr_email=$17, ldap_attr_display_name=$18,
			ldap_start_tls=$19, ldap_insecure_tls=$20, ldap_auto_provision=$21, ldap_skip_mfa=$22, ldap_default_role=$23,
			saml_idp_metadata_url=$24, saml_idp_entity_id=$25, saml_idp_sso_url=$26, saml_idp_cert_pem=$27,
			saml_sp_entity_id=$28, saml_sp_key_enc=$29,
			saml_attr_username=$30, saml_attr_email=$31, saml_attr_display_name=$32,
			saml_auto_provision=$33, saml_skip_mfa=$34, saml_default_role=$35,
			saml_group_attr=$36, saml_group_role_map=$37,
			scim_enabled=$38, scim_token_enc=$39, scim_default_role=$40,
			radius_host=$41, radius_nas_id=$42, radius_timeout_sec=$43, radius_secret_enc=$44,
			radius_auto_provision=$45, radius_skip_mfa=$46, radius_default_role=$47,
			updated_at=NOW(), updated_by=$48
		WHERE id=1`,
		1, mode, publicURL,
		strings.TrimSpace(in.OIDCIssuer), strings.TrimSpace(in.OIDCClientID), oidcSec, strings.TrimSpace(in.OIDCScopes),
		in.OIDCAutoProvision, in.OIDCSkipMFA, strings.TrimSpace(in.OIDCDefaultRole),
		strings.TrimSpace(in.LDAPURL), strings.TrimSpace(in.LDAPBindDN), ldapSec, strings.TrimSpace(in.LDAPUserBaseDN), strings.TrimSpace(in.LDAPUserFilter),
		strings.TrimSpace(in.LDAPAttrUsername), strings.TrimSpace(in.LDAPAttrEmail), strings.TrimSpace(in.LDAPAttrDisplayName),
		in.LDAPStartTLS, in.LDAPInsecureTLS, in.LDAPAutoProvision, in.LDAPSkipMFA, strings.TrimSpace(in.LDAPDefaultRole),
		strings.TrimSpace(in.SAMLIdPMetadataURL), strings.TrimSpace(in.SAMLIdPEntityID), strings.TrimSpace(in.SAMLIdPSSOURL), strings.TrimSpace(in.SAMLIdPCertPEM),
		spEntity, samlKeyEnc,
		strings.TrimSpace(in.SAMLAttrUsername), strings.TrimSpace(in.SAMLAttrEmail), strings.TrimSpace(in.SAMLAttrDisplayName),
		in.SAMLAutoProvision, in.SAMLSkipMFA, strings.TrimSpace(in.SAMLDefaultRole),
		strings.TrimSpace(in.SAMLGroupAttr), in.SAMLGroupRoleMap,
		in.SCIMEnabled, scimEnc, in.SCIMDefaultRole,
		strings.TrimSpace(in.RADIUSHost), strings.TrimSpace(in.RADIUSNASID), in.RADIUSTimeoutSec, radiusSec,
		in.RADIUSAutoProvision, in.RADIUSSkipMFA, strings.TrimSpace(in.RADIUSDefaultRole),
		actorID,
	)
	if err != nil {
		return AuthSettings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "settings.auth.updated", "settings", "auth", ip, ua, map[string]any{"mode": mode})
	if err := s.upsertDefaultIdP(ctx, in); err != nil {
		return AuthSettings{}, err
	}
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

func generateSAMLSPKeyPEM(commonName string) ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if commonName == "" {
		commonName = "keeppam-saml-sp"
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"KeepPAM"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	var out strings.Builder
	_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	_ = pem.Encode(&out, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return []byte(out.String()), nil
}

func IsNotFound(err error) bool { return err == pgx.ErrNoRows }
