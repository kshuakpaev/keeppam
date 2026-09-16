package filevault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/store"
)

const MaxBytes = 32 << 20

var (
	ErrTooLarge     = errors.New("file exceeds 32 MiB")
	ErrSelfApprove  = errors.New("cannot approve own request")
	ErrNotPending   = errors.New("grant is not pending")
	ErrNoAccess     = errors.New("no download grant")
	ErrExpired      = errors.New("grant expired")
	ErrEmpty        = errors.New("empty file")
	ErrInvalidName  = errors.New("invalid file name")
)

type File struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	ContentType string     `json:"content_type"`
	SHA256      string     `json:"sha256"`
	SizeBytes   int64      `json:"size_bytes"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	Access      string     `json:"access,omitempty"`
}

type Grant struct {
	ID          uuid.UUID  `json:"id"`
	FileID      uuid.UUID  `json:"file_id"`
	RequesterID uuid.UUID  `json:"requester_id"`
	Reason      string     `json:"reason"`
	TTLMinutes  int        `json:"ttl_minutes"`
	Status      string     `json:"status"`
	ApproverID  *uuid.UUID `json:"approver_id,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	FileName    string     `json:"file_name,omitempty"`
	Requester   string     `json:"requester,omitempty"`
}

type Service struct {
	db  *store.DB
	env *crypto.Envelope
	aud *audit.Service
}

func New(db *store.DB, env *crypto.Envelope, aud *audit.Service) *Service {
	return &Service{db: db, env: env, aud: aud}
}

func (s *Service) List(ctx context.Context, actor uuid.UUID, custodian bool) ([]File, error) {
	_ = s.ExpireStale(ctx)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, content_type, sha256, size_bytes, created_by, created_at
		FROM protected_files ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []File
	for rows.Next() {
		var f File
		if err := rows.Scan(&f.ID, &f.Name, &f.Description, &f.ContentType, &f.SHA256, &f.SizeBytes, &f.CreatedBy, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if out == nil {
		out = []File{}
	}
	if custodian {
		for i := range out {
			out[i].Access = "custodian"
		}
		return out, nil
	}
	access := map[uuid.UUID]string{}
	if actor != uuid.Nil {
		grows, err := s.db.Pool.Query(ctx, `
			SELECT file_id, status FROM protected_file_grants
			WHERE requester_id=$1 AND (
				status='pending' OR (status='approved' AND expires_at IS NOT NULL AND expires_at > NOW())
			)`, actor)
		if err != nil {
			return nil, err
		}
		defer grows.Close()
		for grows.Next() {
			var fid uuid.UUID
			var st string
			if err := grows.Scan(&fid, &st); err != nil {
				return nil, err
			}
			if st == "approved" || access[fid] == "" {
				access[fid] = st
			}
		}
		if err := grows.Err(); err != nil {
			return nil, err
		}
	}
	for i := range out {
		if a, ok := access[out[i].ID]; ok {
			out[i].Access = a
		} else {
			out[i].Access = "none"
		}
	}
	return out, nil
}

func (s *Service) Upload(ctx context.Context, actor uuid.UUID, name, desc, ctype string, raw []byte, ip, ua string) (File, error) {
	name = sanitizeName(name)
	if name == "" {
		return File{}, ErrInvalidName
	}
	if len(raw) == 0 {
		return File{}, ErrEmpty
	}
	if len(raw) > MaxBytes {
		return File{}, ErrTooLarge
	}
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	enc, err := s.env.Encrypt(raw)
	if err != nil {
		return File{}, err
	}
	sum := sha256.Sum256(raw)
	f := File{
		ID: store.NewID(), Name: name, Description: desc, ContentType: ctype,
		SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(raw)),
		CreatedBy: &actor, CreatedAt: time.Now().UTC(),
	}
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO protected_files (id, name, description, content_type, sha256, size_bytes, blob_enc, created_by, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		f.ID, f.Name, f.Description, f.ContentType, f.SHA256, f.SizeBytes, enc, actor, f.CreatedAt)
	if err != nil {
		return File{}, err
	}
	_ = s.aud.Record(ctx, &actor, "file.vault.uploaded", "protected_file", f.ID.String(), ip, ua, map[string]any{
		"name": f.Name, "sha256": f.SHA256, "size": f.SizeBytes,
	})
	return f, nil
}

func (s *Service) Delete(ctx context.Context, actor, id uuid.UUID, ip, ua string) error {
	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM protected_files WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	_ = s.aud.Record(ctx, &actor, "file.vault.deleted", "protected_file", id.String(), ip, ua, nil)
	return nil
}

func (s *Service) Request(ctx context.Context, actor, fileID uuid.UUID, reason string, ttl int, ip, ua string) (Grant, error) {
	if ttl <= 0 {
		ttl = 60
	}
	if ttl > 10080 {
		ttl = 10080
	}
	var exists bool
	if err := s.db.Pool.QueryRow(ctx, `SELECT TRUE FROM protected_files WHERE id=$1`, fileID).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Grant{}, pgx.ErrNoRows
		}
		return Grant{}, err
	}
	g := Grant{
		ID: store.NewID(), FileID: fileID, RequesterID: actor, Reason: reason,
		TTLMinutes: ttl, Status: "pending", CreatedAt: time.Now().UTC(),
	}
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO protected_file_grants (id, file_id, requester_id, reason, ttl_minutes, status, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		g.ID, g.FileID, g.RequesterID, g.Reason, g.TTLMinutes, g.Status, g.CreatedAt)
	if err != nil {
		return Grant{}, err
	}
	_ = s.aud.Record(ctx, &actor, "file.vault.requested", "protected_file", fileID.String(), ip, ua, map[string]any{
		"grant_id": g.ID.String(), "reason": reason, "ttl_minutes": ttl,
	})
	return g, nil
}

func (s *Service) Decide(ctx context.Context, actor, grantID uuid.UUID, approve bool, ip, ua string) (Grant, error) {
	g, err := s.getGrant(ctx, grantID)
	if err != nil {
		return Grant{}, err
	}
	if g.Status != "pending" {
		return Grant{}, ErrNotPending
	}
	if g.RequesterID == actor {
		return Grant{}, ErrSelfApprove
	}
	now := time.Now().UTC()
	status := "denied"
	var exp *time.Time
	if approve {
		status = "approved"
		t := now.Add(time.Duration(g.TTLMinutes) * time.Minute)
		exp = &t
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE protected_file_grants
		SET status=$2, approver_id=$3, decided_at=$4, expires_at=$5
		WHERE id=$1`, grantID, status, actor, now, exp)
	if err != nil {
		return Grant{}, err
	}
	action := "file.vault.denied"
	if approve {
		action = "file.vault.approved"
	}
	_ = s.aud.Record(ctx, &actor, action, "protected_file", g.FileID.String(), ip, ua, map[string]any{
		"grant_id": grantID.String(), "requester_id": g.RequesterID.String(),
	})
	g.Status = status
	g.ApproverID = &actor
	g.DecidedAt = &now
	g.ExpiresAt = exp
	return g, nil
}

func (s *Service) ListGrants(ctx context.Context, pendingOnly bool) ([]Grant, error) {
	q := `
		SELECT g.id, g.file_id, g.requester_id, g.reason, g.ttl_minutes, g.status, g.approver_id,
		       g.decided_at, g.expires_at, g.created_at, f.name, u.username
		FROM protected_file_grants g
		JOIN protected_files f ON f.id = g.file_id
		JOIN users u ON u.id = g.requester_id`
	if pendingOnly {
		q += ` WHERE g.status='pending'`
	}
	q += ` ORDER BY g.created_at DESC LIMIT 300`
	rows, err := s.db.Pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.ID, &g.FileID, &g.RequesterID, &g.Reason, &g.TTLMinutes, &g.Status, &g.ApproverID,
			&g.DecidedAt, &g.ExpiresAt, &g.CreatedAt, &g.FileName, &g.Requester); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if out == nil {
		out = []Grant{}
	}
	return out, rows.Err()
}

func (s *Service) Download(ctx context.Context, actor, fileID uuid.UUID, custodian bool, ip, ua string) (File, []byte, error) {
	var f File
	var blob []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, content_type, sha256, size_bytes, blob_enc, created_by, created_at
		FROM protected_files WHERE id=$1`, fileID).Scan(
		&f.ID, &f.Name, &f.Description, &f.ContentType, &f.SHA256, &f.SizeBytes, &blob, &f.CreatedBy, &f.CreatedAt)
	if err != nil {
		return File{}, nil, err
	}
	if !custodian {
		ok, err := s.hasLiveGrant(ctx, actor, fileID)
		if err != nil {
			return File{}, nil, err
		}
		if !ok {
			return File{}, nil, ErrNoAccess
		}
	}
	plain, err := s.env.Decrypt(blob)
	if err != nil {
		return File{}, nil, err
	}
	_ = s.aud.Record(ctx, &actor, "file.vault.downloaded", "protected_file", fileID.String(), ip, ua, map[string]any{
		"name": f.Name, "custodian": custodian,
	})
	return f, plain, nil
}

func (s *Service) hasLiveGrant(ctx context.Context, actor, fileID uuid.UUID) (bool, error) {
	var n int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM protected_file_grants
		WHERE file_id=$1 AND requester_id=$2 AND status='approved'
		  AND expires_at IS NOT NULL AND expires_at > NOW()`, fileID, actor).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Service) getGrant(ctx context.Context, id uuid.UUID) (Grant, error) {
	var g Grant
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, file_id, requester_id, reason, ttl_minutes, status, approver_id, decided_at, expires_at, created_at
		FROM protected_file_grants WHERE id=$1`, id).Scan(
		&g.ID, &g.FileID, &g.RequesterID, &g.Reason, &g.TTLMinutes, &g.Status, &g.ApproverID, &g.DecidedAt, &g.ExpiresAt, &g.CreatedAt)
	return g, err
}

func sanitizeName(name string) string {
	name = trimPath(name)
	if name == "" || !utf8.ValidString(name) || len(name) > 255 {
		return ""
	}
	return name
}

func trimPath(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' || name[i] == '\\' {
			return name[i+1:]
		}
	}
	return name
}

func (s *Service) ExpireStale(ctx context.Context) error {
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE protected_file_grants SET status='expired'
		WHERE status='approved' AND expires_at IS NOT NULL AND expires_at < NOW()`)
	return err
}

func ErrFmt(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v", err)
}
