package users

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/store"
)

// VaultSSHKey is a per-user private key stored in the vault. The private PEM is never returned.
type VaultSSHKey struct {
	ID          uuid.UUID  `json:"id"`
	UserID      uuid.UUID  `json:"user_id"`
	Name        string     `json:"name"`
	PublicKey   string     `json:"public_key"`
	Fingerprint string     `json:"fingerprint"`
	Active      bool       `json:"active"`
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
}

type AddVaultSSHKeyInput struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	Active     bool   `json:"active"`
}

func (s *Service) ListVaultSSHKeys(ctx context.Context, userID uuid.UUID) ([]VaultSSHKey, error) {
	if _, err := s.db.GetUserByID(ctx, userID); err != nil {
		return nil, err
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, user_id, name, public_key, fingerprint, active, created_at, created_by
		FROM user_vault_ssh_keys WHERE user_id=$1
		ORDER BY active DESC, created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VaultSSHKey
	for rows.Next() {
		var k VaultSSHKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.PublicKey, &k.Fingerprint, &k.Active, &k.CreatedAt, &k.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if out == nil {
		out = []VaultSSHKey{}
	}
	return out, rows.Err()
}

func (s *Service) AddVaultSSHKey(ctx context.Context, actorID, userID uuid.UUID, in AddVaultSSHKeyInput, ip, ua string) (VaultSSHKey, error) {
	if s == nil || s.env == nil {
		return VaultSSHKey{}, fmt.Errorf("vault encryption not configured")
	}
	if _, err := s.db.GetUserByID(ctx, userID); err != nil {
		return VaultSSHKey{}, err
	}
	_, pubLine, fp, err := parseVaultPrivateKey(in.PrivateKey)
	if err != nil {
		return VaultSSHKey{}, err
	}
	raw := []byte(in.PrivateKey)
	defer crypto.Wipe(raw)
	enc, err := s.env.Encrypt(raw)
	if err != nil {
		return VaultSSHKey{}, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "vault"
	}
	id := store.NewID()
	now := time.Now().UTC()

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return VaultSSHKey{}, err
	}
	defer tx.Rollback(ctx)

	var activeCount int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM user_vault_ssh_keys WHERE user_id=$1 AND active`, userID).Scan(&activeCount); err != nil {
		return VaultSSHKey{}, err
	}
	active := in.Active || activeCount == 0
	if active {
		if _, err := tx.Exec(ctx, `UPDATE user_vault_ssh_keys SET active=false WHERE user_id=$1`, userID); err != nil {
			return VaultSSHKey{}, err
		}
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO user_vault_ssh_keys (id, user_id, name, public_key, fingerprint, private_enc, active, created_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		id, userID, name, pubLine, fp, enc, active, now, actorID)
	if err != nil {
		if strings.Contains(err.Error(), "user_vault_ssh_keys_user_id_fingerprint") || strings.Contains(err.Error(), "duplicate") {
			return VaultSSHKey{}, fmt.Errorf("ssh key already registered")
		}
		return VaultSSHKey{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return VaultSSHKey{}, err
	}
	_ = s.audit.Record(ctx, &actorID, "user.vault_ssh_key.added", "user", userID.String(), ip, ua, map[string]any{
		"fingerprint": fp, "name": name, "active": active,
	})
	return VaultSSHKey{
		ID: id, UserID: userID, Name: name, PublicKey: pubLine,
		Fingerprint: fp, Active: active, CreatedAt: now, CreatedBy: &actorID,
	}, nil
}

func (s *Service) SetActiveVaultSSHKey(ctx context.Context, actorID, userID, keyID uuid.UUID, ip, ua string) error {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var n int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM user_vault_ssh_keys WHERE id=$1 AND user_id=$2`, keyID, userID).Scan(&n); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("not found")
		}
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE user_vault_ssh_keys SET active=false WHERE user_id=$1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE user_vault_ssh_keys SET active=true WHERE id=$1 AND user_id=$2`, keyID, userID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	_ = s.audit.Record(ctx, &actorID, "user.vault_ssh_key.activated", "user", userID.String(), ip, ua, map[string]any{
		"key_id": keyID.String(),
	})
	return nil
}

func (s *Service) DeleteVaultSSHKey(ctx context.Context, actorID, userID, keyID uuid.UUID, ip, ua string) error {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var active bool
	err = tx.QueryRow(ctx, `DELETE FROM user_vault_ssh_keys WHERE id=$1 AND user_id=$2 RETURNING active`, keyID, userID).Scan(&active)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("not found")
		}
		return err
	}
	if active {
		_, err = tx.Exec(ctx, `
			UPDATE user_vault_ssh_keys SET active=true
			WHERE id = (
				SELECT id FROM user_vault_ssh_keys WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1
			)`, userID)
		if err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	_ = s.audit.Record(ctx, &actorID, "user.vault_ssh_key.deleted", "user", userID.String(), ip, ua, map[string]any{
		"key_id": keyID.String(),
	})
	return nil
}

// VaultPublicKey returns the stored public line for install onto a server.
func (s *Service) VaultPublicKey(ctx context.Context, userID, keyID uuid.UUID) (string, error) {
	var pub string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT public_key FROM user_vault_ssh_keys WHERE id=$1 AND user_id=$2`, keyID, userID).Scan(&pub)
	if err != nil {
		return "", fmt.Errorf("not found")
	}
	return pub, nil
}

// ApplyVaultSSHKey replaces account auth with the user's active vault private key
// when the account method is user_ssh_key. Other methods are left unchanged.
func (s *Service) ApplyVaultSSHKey(ctx context.Context, userID uuid.UUID, creds *assets.TargetCreds) error {
	if creds == nil || creds.AuthMethod != "user_ssh_key" {
		return nil
	}
	if s == nil || s.env == nil {
		return fmt.Errorf("vault encryption not configured")
	}
	var enc []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT private_enc FROM user_vault_ssh_keys
		WHERE user_id=$1 AND active
		ORDER BY created_at DESC LIMIT 1`, userID).Scan(&enc)
	if err != nil || len(enc) == 0 {
		return fmt.Errorf("user has no active vault SSH key")
	}
	plain, err := s.env.Decrypt(enc)
	if err != nil {
		return err
	}
	defer crypto.Wipe(plain)
	if _, _, _, err := parseVaultPrivateKey(string(plain)); err != nil {
		return fmt.Errorf("stored vault ssh key: %w", err)
	}
	creds.Secret = string(plain)
	creds.AuthMethod = "ssh_key"
	return nil
}

func parseVaultPrivateKey(raw string) (ssh.Signer, string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, "", "", fmt.Errorf("private_key required")
	}
	signer, err := ssh.ParsePrivateKey([]byte(raw))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "passphrase") || strings.Contains(strings.ToLower(err.Error()), "encrypted") {
			return nil, "", "", fmt.Errorf("private key must be without a passphrase")
		}
		return nil, "", "", fmt.Errorf("invalid private key: %w", err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return signer, pubLine, ssh.FingerprintSHA256(signer.PublicKey()), nil
}
