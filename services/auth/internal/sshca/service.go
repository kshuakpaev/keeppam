package sshca

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/sshkrb"
	"github.com/keeppam/auth/internal/store"
)

const (
	ModeVault  = "vault_secret"
	ModeCert   = "ssh_cert"
	ModeGSSAPI = "gssapi"
)

type Settings struct {
	SSHAuthMode     string     `json:"ssh_auth_mode"`
	SSHCAPublic     string     `json:"ssh_ca_public"`
	SSHCertTTLHours int        `json:"ssh_cert_ttl_hours"`
	HasSSHCA        bool       `json:"has_ssh_ca"`
	RotateCA        bool       `json:"rotate_ca,omitempty"`
	Krb5Realm       string     `json:"krb5_realm"`
	Krb5Config      string     `json:"krb5_config"`
	Krb5Principal   string     `json:"krb5_principal"`
	Krb5SPNTemplate string     `json:"krb5_spn_template"`
	HasKrb5Keytab   bool       `json:"has_krb5_keytab"`
	Krb5Keytab      string     `json:"krb5_keytab,omitempty"` // write-only base64 or raw upload via API as string bytes
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
}

type Service struct {
	db  *store.DB
	env *crypto.Envelope
	aud *audit.Service
}

func New(db *store.DB, env *crypto.Envelope, aud *audit.Service) *Service {
	return &Service{db: db, env: env, aud: aud}
}

func (s *Service) Get(ctx context.Context) (Settings, error) {
	var st Settings
	var enc, ktEnc []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT ssh_auth_mode, COALESCE(ssh_ca_public,''), ssh_cert_ttl_hours,
		       ssh_ca_private_enc, updated_at,
		       COALESCE(krb5_realm,''), COALESCE(krb5_config,''), COALESCE(krb5_principal,''),
		       COALESCE(krb5_spn_template,'host/%h'), krb5_keytab_enc
		FROM ssh_settings WHERE id=1`).Scan(
		&st.SSHAuthMode, &st.SSHCAPublic, &st.SSHCertTTLHours, &enc, &st.UpdatedAt,
		&st.Krb5Realm, &st.Krb5Config, &st.Krb5Principal, &st.Krb5SPNTemplate, &ktEnc)
	if err != nil {
		return Settings{}, err
	}
	st.HasSSHCA = len(enc) > 0
	st.HasKrb5Keytab = len(ktEnc) > 0
	if st.SSHAuthMode == "" {
		st.SSHAuthMode = ModeVault
	}
	if st.SSHCertTTLHours <= 0 {
		st.SSHCertTTLHours = 8
	}
	if st.Krb5SPNTemplate == "" {
		st.Krb5SPNTemplate = "host/%h"
	}
	return st, nil
}

func (s *Service) Mode(ctx context.Context) string {
	st, err := s.Get(ctx)
	if err != nil {
		return ModeVault
	}
	return st.SSHAuthMode
}

func (s *Service) Update(ctx context.Context, actorID uuid.UUID, in Settings, ip, ua string) (Settings, error) {
	cur, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	mode := strings.TrimSpace(in.SSHAuthMode)
	if mode == "" {
		mode = cur.SSHAuthMode
	}
	if mode != ModeVault && mode != ModeCert && mode != ModeGSSAPI {
		return Settings{}, fmt.Errorf("ssh_auth_mode must be vault_secret, ssh_cert, or gssapi")
	}
	ttl := in.SSHCertTTLHours
	if ttl == 0 {
		ttl = cur.SSHCertTTLHours
	}
	if ttl < 1 || ttl > 168 {
		return Settings{}, fmt.Errorf("ssh_cert_ttl_hours must be 1..168")
	}

	var enc []byte
	pub := cur.SSHCAPublic
	needCA := mode == ModeCert && (!cur.HasSSHCA || in.RotateCA)
	if needCA {
		privPEM, pubLine, err := generateCA()
		if err != nil {
			return Settings{}, err
		}
		enc, err = s.env.Encrypt(privPEM)
		if err != nil {
			return Settings{}, err
		}
		pub = pubLine
	}

	realm := cur.Krb5Realm
	if strings.TrimSpace(in.Krb5Realm) != "" {
		realm = strings.ToUpper(strings.TrimSpace(in.Krb5Realm))
	}
	krbCfg := cur.Krb5Config
	if in.Krb5Config != "" {
		krbCfg = in.Krb5Config
	}
	princ := cur.Krb5Principal
	if strings.TrimSpace(in.Krb5Principal) != "" {
		princ = strings.TrimSpace(in.Krb5Principal)
	}
	spnTpl := cur.Krb5SPNTemplate
	if strings.TrimSpace(in.Krb5SPNTemplate) != "" {
		spnTpl = strings.TrimSpace(in.Krb5SPNTemplate)
	}
	if spnTpl == "" {
		spnTpl = "host/%h"
	}
	if mode == ModeGSSAPI && realm == "" {
		return Settings{}, fmt.Errorf("krb5_realm required for gssapi mode")
	}

	var ktEncAny any
	if strings.TrimSpace(in.Krb5Keytab) != "" {
		raw := decodeMaybeBase64(in.Krb5Keytab)
		encKt, err := s.env.Encrypt(raw)
		if err != nil {
			return Settings{}, err
		}
		ktEncAny = encKt
	}

	if len(enc) > 0 {
		_, err = s.db.Pool.Exec(ctx, `
			UPDATE ssh_settings
			SET ssh_auth_mode=$1, ssh_cert_ttl_hours=$2, ssh_ca_private_enc=$3, ssh_ca_public=$4,
			    krb5_realm=$5, krb5_config=$6, krb5_principal=$7, krb5_spn_template=$8,
			    krb5_keytab_enc=COALESCE($9, krb5_keytab_enc),
			    updated_at=NOW(), updated_by=$10
			WHERE id=1`, mode, ttl, enc, pub, realm, krbCfg, princ, spnTpl, ktEncAny, actorID)
	} else {
		_, err = s.db.Pool.Exec(ctx, `
			UPDATE ssh_settings
			SET ssh_auth_mode=$1, ssh_cert_ttl_hours=$2,
			    krb5_realm=$3, krb5_config=$4, krb5_principal=$5, krb5_spn_template=$6,
			    krb5_keytab_enc=COALESCE($7, krb5_keytab_enc),
			    updated_at=NOW(), updated_by=$8
			WHERE id=1`, mode, ttl, realm, krbCfg, princ, spnTpl, ktEncAny, actorID)
	}
	if err != nil {
		return Settings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "settings.ssh.updated", "ssh_settings", "1", ip, ua, map[string]any{
		"ssh_auth_mode": mode, "ttl_hours": ttl, "rotated_ca": needCA, "krb5_realm": realm,
	})
	return s.Get(ctx)
}

// SignUser returns an ephemeral cert signer for the target account username (principal).
func (s *Service) SignUser(ctx context.Context, principal string) (ssh.Signer, error) {
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return nil, fmt.Errorf("empty principal")
	}
	var enc []byte
	var ttl int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT ssh_ca_private_enc, ssh_cert_ttl_hours FROM ssh_settings WHERE id=1`).Scan(&enc, &ttl)
	if err != nil {
		return nil, err
	}
	if len(enc) == 0 {
		return nil, fmt.Errorf("SSH CA not generated; save ssh_cert mode in Config")
	}
	if ttl < 1 {
		ttl = 8
	}
	plain, err := s.env.Decrypt(enc)
	if err != nil {
		return nil, err
	}
	caSigner, err := ssh.ParsePrivateKey(plain)
	if err != nil {
		return nil, fmt.Errorf("parse CA: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	userSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "keeppam:" + principal,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(now.Add(-1 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(time.Duration(ttl) * time.Hour).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-agent-forwarding": "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, fmt.Errorf("sign cert: %w", err)
	}
	return ssh.NewCertSigner(cert, userSigner)
}

func generateCA() (privPEM []byte, pubLine string, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, "", err
	}
	privPEM = pem.EncodeToMemory(block)
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, "", err
	}
	pubLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " keeppam-ca"
	return privPEM, pubLine, nil
}

func decodeMaybeBase64(s string) []byte {
	s = strings.TrimSpace(s)
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil && len(decoded) > 16 {
		return decoded
	}
	return []byte(s)
}

// KerberosConfig returns runtime settings for sshkrb (keytab decrypted when present).
func (s *Service) KerberosConfig(ctx context.Context) (sshkrb.Config, []byte, error) {
	st, err := s.Get(ctx)
	if err != nil {
		return sshkrb.Config{}, nil, err
	}
	var ktEnc []byte
	_ = s.db.Pool.QueryRow(ctx, `SELECT krb5_keytab_enc FROM ssh_settings WHERE id=1`).Scan(&ktEnc)
	var kt []byte
	if len(ktEnc) > 0 {
		kt, err = s.env.Decrypt(ktEnc)
		if err != nil {
			return sshkrb.Config{}, nil, err
		}
	}
	return sshkrb.Config{
		Realm: st.Krb5Realm, Krb5Config: st.Krb5Config,
		Principal: st.Krb5Principal, Keytab: kt, SPNTemplate: st.Krb5SPNTemplate,
	}, kt, nil
}
