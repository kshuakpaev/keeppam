package recarch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/recstore"
	"github.com/keeppam/auth/internal/store"
)

const archiveLock int64 = 77046

type Settings struct {
	Enabled         bool       `json:"enabled"`
	Backend         string     `json:"backend"`
	AgeDays         int        `json:"age_days"`
	IntervalMinutes int        `json:"interval_minutes"`
	DeleteLocal     bool       `json:"delete_local"`
	NFSPath         string     `json:"nfs_path"`
	SMBHost         string     `json:"smb_host"`
	SMBShare        string     `json:"smb_share"`
	SMBUser         string     `json:"smb_user"`
	SMBDomain       string     `json:"smb_domain"`
	SMBPassword     string     `json:"smb_password,omitempty"`
	HasSMBPassword  bool       `json:"has_smb_password"`
	LastRunAt       *time.Time `json:"last_run_at,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	LastCopied      int        `json:"last_copied"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
}

type Stats struct {
	Copied  int `json:"copied"`
	Skipped int `json:"skipped"`
	Failed  int `json:"failed"`
}

type Service struct {
	db    *store.DB
	aud   *audit.Service
	env   *crypto.Envelope
	inner recstore.Store
}

func New(db *store.DB, aud *audit.Service, env *crypto.Envelope, inner recstore.Store) *Service {
	return &Service{db: db, aud: aud, env: env, inner: inner}
}

func (s *Service) Get(ctx context.Context) (Settings, error) {
	var out Settings
	var enc []byte
	var updated time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT enabled, backend, age_days, interval_minutes, delete_local,
			nfs_path, smb_host, smb_share, smb_user, smb_domain, smb_password_enc,
			last_run_at, last_error, last_copied, updated_at
		FROM archive_settings WHERE id=1`).Scan(
		&out.Enabled, &out.Backend, &out.AgeDays, &out.IntervalMinutes, &out.DeleteLocal,
		&out.NFSPath, &out.SMBHost, &out.SMBShare, &out.SMBUser, &out.SMBDomain, &enc,
		&out.LastRunAt, &out.LastError, &out.LastCopied, &updated,
	)
	if err != nil {
		return out, err
	}
	out.HasSMBPassword = len(enc) > 0
	out.UpdatedAt = &updated
	return out, nil
}

func (s *Service) Update(ctx context.Context, actorID uuid.UUID, in Settings, ip, ua string) (Settings, error) {
	cur, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	backend := strings.ToLower(strings.TrimSpace(in.Backend))
	if backend == "" {
		backend = cur.Backend
	}
	if backend != "nfs" && backend != "smb" {
		return Settings{}, fmt.Errorf("backend must be nfs|smb")
	}
	age := in.AgeDays
	if age < 0 || age > 3650 {
		return Settings{}, fmt.Errorf("age_days must be 0..3650")
	}
	iv := in.IntervalMinutes
	if iv < 5 {
		iv = 60
	}
	if iv > 1440 {
		iv = 1440
	}
	var enc []byte
	_ = s.db.Pool.QueryRow(ctx, `SELECT smb_password_enc FROM archive_settings WHERE id=1`).Scan(&enc)
	if strings.TrimSpace(in.SMBPassword) != "" {
		enc, err = s.env.Encrypt([]byte(strings.TrimSpace(in.SMBPassword)))
		if err != nil {
			return Settings{}, err
		}
	}
	if in.Enabled {
		if backend == "nfs" && strings.TrimSpace(in.NFSPath) == "" {
			return Settings{}, fmt.Errorf("nfs_path required")
		}
		if backend == "smb" {
			if strings.TrimSpace(in.SMBHost) == "" || strings.TrimSpace(in.SMBShare) == "" || strings.TrimSpace(in.SMBUser) == "" {
				return Settings{}, fmt.Errorf("smb host, share and user required")
			}
			if len(enc) == 0 {
				return Settings{}, fmt.Errorf("smb_password required")
			}
		}
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE archive_settings SET
			enabled=$1, backend=$2, age_days=$3, interval_minutes=$4, delete_local=$5,
			nfs_path=$6, smb_host=$7, smb_share=$8, smb_user=$9, smb_domain=$10, smb_password_enc=$11,
			updated_at=NOW(), updated_by=$12
		WHERE id=1`,
		in.Enabled, backend, age, iv, in.DeleteLocal,
		strings.TrimSpace(in.NFSPath), strings.TrimSpace(in.SMBHost), strings.TrimSpace(in.SMBShare),
		strings.TrimSpace(in.SMBUser), strings.TrimSpace(in.SMBDomain), enc, actorID,
	)
	if err != nil {
		return Settings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "settings.archive.updated", "settings", "archive", ip, ua, map[string]any{
		"backend": backend, "enabled": in.Enabled,
	})
	return s.Get(ctx)
}

func (s *Service) dest(ctx context.Context, st Settings) (Dest, error) {
	switch strings.ToLower(st.Backend) {
	case "smb":
		var enc []byte
		if err := s.db.Pool.QueryRow(ctx, `SELECT smb_password_enc FROM archive_settings WHERE id=1`).Scan(&enc); err != nil {
			return nil, err
		}
		pass := ""
		if len(enc) > 0 {
			b, err := s.env.Decrypt(enc)
			if err != nil {
				return nil, err
			}
			pass = string(b)
		}
		return newSMBDest(st.SMBHost, st.SMBShare, st.SMBUser, st.SMBDomain, pass)
	default:
		return newNFSDest(st.NFSPath)
	}
}

func (s *Service) Run(ctx context.Context) {
	for {
		st, err := s.Get(ctx)
		wait := 60 * time.Minute
		if err == nil && st.IntervalMinutes >= 5 {
			wait = time.Duration(st.IntervalMinutes) * time.Minute
		}
		if err == nil && st.Enabled {
			if _, runErr := s.SyncOnce(ctx); runErr != nil {
				slog.Warn("archive sync", "err", runErr)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (s *Service) SyncOnce(ctx context.Context) (Stats, error) {
	var stats Stats
	var got bool
	if err := s.db.Pool.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, archiveLock).Scan(&got); err != nil {
		return stats, err
	}
	if !got {
		return stats, nil
	}
	defer func() {
		_, _ = s.db.Pool.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, archiveLock)
	}()

	st, err := s.Get(ctx)
	if err != nil {
		return stats, err
	}
	if !st.Enabled {
		return stats, fmt.Errorf("archive disabled")
	}
	dst, err := s.dest(ctx, st)
	if err != nil {
		_ = s.noteRun(ctx, stats, err)
		return stats, err
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -st.AgeDays)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, recording_path FROM sessions
		WHERE status IN ('ended','failed')
		  AND recording_path <> ''
		  AND NOT COALESCE(archived, FALSE)
		  AND COALESCE(ended_at, created_at) < $1
		ORDER BY COALESCE(ended_at, created_at) ASC
		LIMIT 200`, cutoff)
	if err != nil {
		_ = s.noteRun(ctx, stats, err)
		return stats, err
	}
	type item struct {
		id   uuid.UUID
		path string
	}
	var list []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.path); err != nil {
			rows.Close()
			return stats, err
		}
		list = append(list, it)
	}
	rows.Close()

	for _, it := range list {
		if err := s.copyOne(ctx, dst, st, it.id, it.path); err != nil {
			slog.Warn("archive copy", "session", it.id.String(), "err", err)
			stats.Failed++
			continue
		}
		stats.Copied++
	}
	_ = s.noteRun(ctx, stats, nil)
	_ = s.aud.Record(ctx, nil, "archive.sync", "settings", "archive", "", "", map[string]any{
		"copied": stats.Copied, "failed": stats.Failed, "backend": dst.Kind(),
	})
	return stats, nil
}

func (s *Service) copyOne(ctx context.Context, dst Dest, st Settings, id uuid.UUID, recPath string) error {
	if s.inner != nil {
		_ = s.inner.EnsureLocal(ctx, recPath)
	}
	primary := recPath
	if best := largestExisting(recPath); best != "" {
		primary = best
	}
	if _, err := os.Stat(primary); err != nil {
		return fmt.Errorf("local recording missing")
	}
	sum, err := fileSHA256(primary)
	if err != nil {
		return err
	}
	for _, p := range recstore.RecordingFiles(recPath) {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		rel := archiveRel(id, p)
		putErr := dst.Put(ctx, rel, f)
		_ = f.Close()
		if putErr != nil {
			return putErr
		}
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE sessions SET archived=TRUE, archive_sha256=$2, archive_backend=$3, archived_at=NOW()
		WHERE id=$1`, id, sum, dst.Kind())
	if err != nil {
		return err
	}
	if st.DeleteLocal && s.inner != nil {
		_, _, _ = s.inner.TryDelete(ctx, recPath)
	}
	return nil
}

func (s *Service) Has(ctx context.Context, recPath string) bool {
	var archived bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(archived, FALSE) FROM sessions WHERE recording_path=$1 LIMIT 1`, recPath).Scan(&archived)
	return err == nil && archived
}

func (s *Service) Restore(ctx context.Context, recPath string) error {
	var id uuid.UUID
	var sha, backend string
	var archived bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, COALESCE(archived, FALSE), COALESCE(archive_sha256,''), COALESCE(archive_backend,'')
		FROM sessions WHERE recording_path=$1
		ORDER BY archived_at DESC NULLS LAST LIMIT 1`, recPath).Scan(&id, &archived, &sha, &backend)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("recording not archived")
		}
		return err
	}
	if !archived {
		return fmt.Errorf("recording not archived")
	}
	st, err := s.Get(ctx)
	if err != nil {
		return err
	}
	if backend != "" {
		st.Backend = backend
	}
	dst, err := s.dest(ctx, st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(recPath), 0o750); err != nil {
		return err
	}
	for _, p := range recstore.RecordingFiles(recPath) {
		rel := archiveRel(id, p)
		if !dst.Exists(ctx, rel) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		tmp := p + ".restore"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			return err
		}
		getErr := dst.Get(ctx, rel, f)
		_ = f.Close()
		if getErr != nil {
			_ = os.Remove(tmp)
			return getErr
		}
		if err := os.Rename(tmp, p); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	if sha != "" {
		got, err := fileSHA256(recPath)
		if err != nil {
			if best := largestExisting(recPath); best != "" {
				got, err = fileSHA256(best)
			}
		}
		if err != nil {
			return err
		}
		if got != sha {
			return fmt.Errorf("archive checksum mismatch")
		}
	}
	return nil
}

func (s *Service) noteRun(ctx context.Context, stats Stats, runErr error) error {
	msg := ""
	if runErr != nil {
		msg = runErr.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
	}
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE archive_settings SET last_run_at=NOW(), last_error=$1, last_copied=$2 WHERE id=1`,
		msg, stats.Copied)
	return err
}

func archiveRel(id uuid.UUID, abs string) string {
	return id.String() + "/" + filepath.Base(abs)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func largestExisting(base string) string {
	best := ""
	var n int64
	for _, p := range recstore.RecordingFiles(base) {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		if st.Size() > n {
			n = st.Size()
			best = p
		}
	}
	return best
}
