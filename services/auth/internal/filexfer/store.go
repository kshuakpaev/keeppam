package filexfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/recstore"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/store"
)

const maxFileBytes = 512 << 20

type File struct {
	ID         uuid.UUID `json:"id"`
	SessionID  uuid.UUID `json:"session_id"`
	Filename   string    `json:"filename"`
	RemotePath string    `json:"remote_path"`
	Protocol   string    `json:"protocol"`
	Direction  string    `json:"direction"`
	SizeBytes  int64     `json:"size_bytes"`
	SHA256     string    `json:"sha256"`
	StoredPath string    `json:"stored_path,omitempty"`
	Captured   bool      `json:"captured"`
	CreatedAt  time.Time `json:"created_at"`
}

type Service struct {
	db   *store.DB
	sess *sessionsvc.Service
	rec  recstore.Store
	root string
}

func New(db *store.DB, sess *sessionsvc.Service, rec recstore.Store, recordingsDir string) *Service {
	root := filepath.Join(recordingsDir, "files")
	return &Service{db: db, sess: sess, rec: rec, root: root}
}

func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, `\`, "/")
	name = filepath.Base(name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return "unnamed"
	}
	if len(name) > 200 {
		name = name[:200]
	}
	return name
}

func (s *Service) dir(sessionID uuid.UUID) string {
	return filepath.Join(s.root, sessionID.String())
}

type SaveMeta struct {
	SessionID  uuid.UUID
	Filename   string
	RemotePath string
	Protocol   string // scp|sftp
	Direction  string // upload|download
	Capture    bool
}

func (s *Service) SaveReader(ctx context.Context, meta SaveMeta, r io.Reader, size int64) error {
	if size < 0 {
		size = 0
	}
	if size > maxFileBytes {
		return fmt.Errorf("file too large (%d > %d)", size, maxFileBytes)
	}
	name := sanitizeName(meta.Filename)
	h := sha256.New()
	var destPath string
	var captured bool
	if meta.Capture {
		if err := os.MkdirAll(s.dir(meta.SessionID), 0o750); err != nil {
			return err
		}
		destPath = filepath.Join(s.dir(meta.SessionID), uniqueName(s.dir(meta.SessionID), name))
		f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
		if err != nil {
			return err
		}
		lr := io.LimitReader(r, size)
		n, err := io.Copy(io.MultiWriter(f, h), lr)
		cerr := f.Close()
		if err != nil {
			_ = os.Remove(destPath)
			return err
		}
		if cerr != nil {
			_ = os.Remove(destPath)
			return cerr
		}
		if size > 0 && n != size {
			_ = os.Remove(destPath)
			return fmt.Errorf("short file: got %d want %d", n, size)
		}
		if size == 0 {
			size = n
		}
		captured = true
		if s.rec != nil {
			_ = s.rec.Sync(ctx, destPath)
		}
	} else {
		n, err := io.Copy(h, io.LimitReader(r, maxFileBytes+1))
		if err != nil {
			return err
		}
		if n > maxFileBytes {
			return fmt.Errorf("file too large")
		}
		size = n
	}
	sum := hex.EncodeToString(h.Sum(nil))
	id := store.NewID()
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO session_files (id, session_id, filename, remote_path, protocol, direction, size_bytes, sha256, stored_path, captured, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())`,
		id, meta.SessionID, name, strings.TrimSpace(meta.RemotePath), meta.Protocol, meta.Direction,
		size, sum, destPath, captured)
	if err != nil {
		if captured {
			_ = os.Remove(destPath)
		}
		return err
	}
	if s.sess != nil {
		_ = s.sess.AddEvent(ctx, meta.SessionID, "file_transfer", map[string]any{
			"filename": name, "path": meta.RemotePath, "protocol": meta.Protocol,
			"direction": meta.Direction, "size": size, "sha256": sum, "captured": captured,
			"file_id": id.String(), "offset": s.sessionOffsetSec(ctx, meta.SessionID),
		})
	}
	return nil
}

func uniqueName(dir, name string) string {
	p := filepath.Join(dir, name)
	if _, err := os.Stat(p); err != nil {
		return name
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 2; i < 1000; i++ {
		cand := fmt.Sprintf("%s-%d%s", base, i, ext)
		if _, err := os.Stat(filepath.Join(dir, cand)); err != nil {
			return cand
		}
	}
	return fmt.Sprintf("%s-%d%s", base, time.Now().UnixNano(), ext)
}

func (s *Service) List(ctx context.Context, sessionID uuid.UUID) ([]File, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, session_id, filename, remote_path, protocol, direction, size_bytes, sha256, stored_path, captured, created_at
		FROM session_files WHERE session_id=$1 ORDER BY created_at, filename`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []File
	for rows.Next() {
		var f File
		if err := rows.Scan(&f.ID, &f.SessionID, &f.Filename, &f.RemotePath, &f.Protocol, &f.Direction,
			&f.SizeBytes, &f.SHA256, &f.StoredPath, &f.Captured, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if out == nil {
		out = []File{}
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, sessionID, fileID uuid.UUID) (File, error) {
	var f File
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, session_id, filename, remote_path, protocol, direction, size_bytes, sha256, stored_path, captured, created_at
		FROM session_files WHERE id=$1 AND session_id=$2`, fileID, sessionID).Scan(
		&f.ID, &f.SessionID, &f.Filename, &f.RemotePath, &f.Protocol, &f.Direction,
		&f.SizeBytes, &f.SHA256, &f.StoredPath, &f.Captured, &f.CreatedAt)
	return f, err
}

func (s *Service) OpenLocal(ctx context.Context, f File) (*os.File, error) {
	if !f.Captured || f.StoredPath == "" {
		return nil, fmt.Errorf("file was not stored (audit mode)")
	}
	if s.rec != nil {
		if err := s.rec.EnsureLocal(ctx, f.StoredPath); err != nil {
			return nil, err
		}
	}
	return os.Open(f.StoredPath)
}

func (s *Service) sessionOffsetSec(ctx context.Context, sessionID uuid.UUID) float64 {
	var created time.Time
	if err := s.db.Pool.QueryRow(ctx, `SELECT created_at FROM sessions WHERE id=$1`, sessionID).Scan(&created); err != nil || created.IsZero() {
		return 0
	}
	sec := time.Since(created).Seconds()
	if sec < 0 {
		return 0
	}
	return sec
}
