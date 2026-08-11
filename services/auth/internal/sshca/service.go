package sshca

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/store"
)

const (
	ModeVault = "vault_secret"
	ModeCert  = "ssh_cert"
)

type Settings struct {
	SSHAuthMode     string     `json:"ssh_auth_mode"`
	SSHCAPublic     string     `json:"ssh_ca_public"`
	SSHCertTTLHours int        `json:"ssh_cert_ttl_hours"`
	HasSSHCA        bool       `json:"has_ssh_ca"`
	RotateCA        bool       `json:"rotate_ca,omitempty"`
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
	var enc []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT ssh_auth_mode, COALESCE(ssh_ca_public,''), ssh_cert_ttl_hours,
		       ssh_ca_private_enc, updated_at
		FROM ssh_settings WHERE id=1`).Scan(
		&st.SSHAuthMode, &st.SSHCAPublic, &st.SSHCertTTLHours, &enc, &st.UpdatedAt)
	if err != nil {
		return Settings{}, err
	}
	st.HasSSHCA = len(enc) > 0
	if st.SSHAuthMode == "" {
		st.SSHAuthMode = ModeVault
	}
	if st.SSHCertTTLHours <= 0 {
		st.SSHCertTTLHours = 8
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
	if mode != ModeVault && mode != ModeCert {
		return Settings{}, fmt.Errorf("ssh_auth_mode must be vault_secret or ssh_cert")
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

	if len(enc) > 0 {
		_, err = s.db.Pool.Exec(ctx, `
			UPDATE ssh_settings
			SET ssh_auth_mode=$1, ssh_cert_ttl_hours=$2, ssh_ca_private_enc=$3, ssh_ca_public=$4,
			    updated_at=NOW(), updated_by=$5
			WHERE id=1`, mode, ttl, enc, pub, actorID)
	} else {
		_, err = s.db.Pool.Exec(ctx, `
			UPDATE ssh_settings
			SET ssh_auth_mode=$1, ssh_cert_ttl_hours=$2, updated_at=NOW(), updated_by=$3
			WHERE id=1`, mode, ttl, actorID)
	}
	if err != nil {
		return Settings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "settings.ssh.updated", "ssh_settings", "1", ip, ua, map[string]any{
		"ssh_auth_mode": mode, "ttl_hours": ttl, "rotated_ca": needCA,
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
