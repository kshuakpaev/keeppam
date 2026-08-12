package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type WebAuthnCredential struct {
	ID              uuid.UUID `json:"id"`
	UserID          uuid.UUID `json:"user_id"`
	Name            string    `json:"name"`
	CredentialID    []byte    `json:"-"`
	PublicKey       []byte    `json:"-"`
	AttestationType string    `json:"attestation_type"`
	Transport       []string  `json:"transport"`
	SignCount       uint32    `json:"sign_count"`
	AAGUID          []byte    `json:"-"`
	BackupEligible  bool      `json:"backup_eligible"`
	BackupState     bool      `json:"backup_state"`
	CreatedAt       time.Time `json:"created_at"`
}

func (db *DB) ListWebAuthnCredentials(ctx context.Context, userID uuid.UUID) ([]WebAuthnCredential, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, user_id, name, credential_id, public_key, attestation_type, transport,
		       sign_count, aaguid, backup_eligible, backup_state, created_at
		FROM user_webauthn_credentials WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		var signCount int64
		if err := rows.Scan(&c.ID, &c.UserID, &c.Name, &c.CredentialID, &c.PublicKey, &c.AttestationType,
			&c.Transport, &signCount, &c.AAGUID, &c.BackupEligible, &c.BackupState, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.SignCount = uint32(signCount)
		if c.Transport == nil {
			c.Transport = []string{}
		}
		out = append(out, c)
	}
	if out == nil {
		out = []WebAuthnCredential{}
	}
	return out, rows.Err()
}

func (db *DB) CountWebAuthnCredentials(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM user_webauthn_credentials WHERE user_id=$1`, userID).Scan(&n)
	return n, err
}

func (db *DB) InsertWebAuthnCredential(ctx context.Context, c WebAuthnCredential) (WebAuthnCredential, error) {
	if c.ID == uuid.Nil {
		c.ID = NewID()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	if c.Transport == nil {
		c.Transport = []string{}
	}
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO user_webauthn_credentials (
			id, user_id, name, credential_id, public_key, attestation_type, transport,
			sign_count, aaguid, backup_eligible, backup_state, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		c.ID, c.UserID, c.Name, c.CredentialID, c.PublicKey, c.AttestationType, c.Transport,
		c.SignCount, c.AAGUID, c.BackupEligible, c.BackupState, c.CreatedAt)
	return c, err
}

func (db *DB) UpdateWebAuthnSignCount(ctx context.Context, userID uuid.UUID, credentialID []byte, signCount uint32, backupState bool) error {
	tag, err := db.Pool.Exec(ctx, `
		UPDATE user_webauthn_credentials
		SET sign_count=$3, backup_state=$4
		WHERE user_id=$1 AND credential_id=$2`, userID, credentialID, signCount, backupState)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (db *DB) DeleteWebAuthnCredentialsByUser(ctx context.Context, userID uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM user_webauthn_credentials WHERE user_id=$1`, userID)
	return err
}

func (db *DB) DeleteWebAuthnCredential(ctx context.Context, userID, credID uuid.UUID) error {
	tag, err := db.Pool.Exec(ctx, `DELETE FROM user_webauthn_credentials WHERE id=$1 AND user_id=$2`, credID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
