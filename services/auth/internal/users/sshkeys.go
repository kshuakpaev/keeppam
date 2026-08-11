package users

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/keeppam/auth/internal/store"
)

type SSHKey struct {
	ID          uuid.UUID  `json:"id"`
	UserID      uuid.UUID  `json:"user_id"`
	Name        string     `json:"name"`
	PublicKey   string     `json:"public_key"`
	Fingerprint string     `json:"fingerprint"`
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
}

type AddSSHKeyInput struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

func (s *Service) ListSSHKeys(ctx context.Context, userID uuid.UUID) ([]SSHKey, error) {
	if _, err := s.db.GetUserByID(ctx, userID); err != nil {
		return nil, err
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, user_id, name, public_key, fingerprint, created_at, created_by
		FROM user_ssh_keys WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SSHKey
	for rows.Next() {
		var k SSHKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.PublicKey, &k.Fingerprint, &k.CreatedAt, &k.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if out == nil {
		out = []SSHKey{}
	}
	return out, rows.Err()
}

func (s *Service) AddSSHKey(ctx context.Context, actorID, userID uuid.UUID, in AddSSHKeyInput, ip, ua string) (SSHKey, error) {
	if _, err := s.db.GetUserByID(ctx, userID); err != nil {
		return SSHKey{}, err
	}
	pub, comment, err := parsePublicKey(in.PublicKey)
	if err != nil {
		return SSHKey{}, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = comment
	}
	if name == "" {
		name = pub.Type()
	}
	fp := ssh.FingerprintSHA256(pub)
	marshaled := strings.TrimSpace(in.PublicKey)
	id := store.NewID()
	now := time.Now().UTC()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO user_ssh_keys (id, user_id, name, public_key, fingerprint, created_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, userID, name, marshaled, fp, now, actorID)
	if err != nil {
		if strings.Contains(err.Error(), "user_ssh_keys_fingerprint_key") || strings.Contains(err.Error(), "duplicate") {
			return SSHKey{}, fmt.Errorf("ssh key already registered")
		}
		return SSHKey{}, err
	}
	_ = s.audit.Record(ctx, &actorID, "user.ssh_key.added", "user", userID.String(), ip, ua, map[string]any{
		"fingerprint": fp, "name": name,
	})
	return SSHKey{
		ID: id, UserID: userID, Name: name, PublicKey: marshaled,
		Fingerprint: fp, CreatedAt: now, CreatedBy: &actorID,
	}, nil
}

func (s *Service) DeleteSSHKey(ctx context.Context, actorID, userID, keyID uuid.UUID, ip, ua string) error {
	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM user_ssh_keys WHERE id=$1 AND user_id=$2`, keyID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	_ = s.audit.Record(ctx, &actorID, "user.ssh_key.deleted", "user", userID.String(), ip, ua, map[string]any{
		"key_id": keyID.String(),
	})
	return nil
}

func parsePublicKey(raw string) (ssh.PublicKey, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, "", fmt.Errorf("public_key required")
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		return nil, "", fmt.Errorf("invalid public key: %w", err)
	}
	return pub, comment, nil
}
