package dr

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/store"
)

type Service struct {
	db            *store.DB
	aud           *audit.Service
	databaseURL   string
	recordingsDir string
}

func New(db *store.DB, aud *audit.Service, databaseURL, recordingsDir string) *Service {
	return &Service{db: db, aud: aud, databaseURL: databaseURL, recordingsDir: recordingsDir}
}

type Settings struct {
	SiteName         string     `json:"site_name"`
	Role             string     `json:"role"`
	RPOMinutes       int        `json:"rpo_minutes"`
	RTOMinutes       int        `json:"rto_minutes"`
	ReplicaDSNHint   string     `json:"replica_dsn_hint"`
	BackupDir        string     `json:"backup_dir"`
	LastBackupAt     *time.Time `json:"last_backup_at,omitempty"`
	LastBackupPath   string     `json:"last_backup_path,omitempty"`
	LastBackupBytes  int64      `json:"last_backup_bytes"`
	LastBackupStatus string     `json:"last_backup_status,omitempty"`
	LastDrillAt      *time.Time `json:"last_drill_at,omitempty"`
	LastDrillNotes   string     `json:"last_drill_notes,omitempty"`
	LastDrillOK      *bool      `json:"last_drill_ok,omitempty"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type SettingsInput struct {
	SiteName       *string `json:"site_name"`
	Role           *string `json:"role"`
	RPOMinutes     *int    `json:"rpo_minutes"`
	RTOMinutes     *int    `json:"rto_minutes"`
	ReplicaDSNHint *string `json:"replica_dsn_hint"`
	BackupDir      *string `json:"backup_dir"`
}

type Status struct {
	Settings       Settings `json:"settings"`
	PrimaryOK      bool     `json:"primary_ok"`
	ReplicaOK      *bool    `json:"replica_ok,omitempty"`
	ReplicaError   string   `json:"replica_error,omitempty"`
	BackupFresh    bool     `json:"backup_fresh"`
	BackupAgeMin   *int     `json:"backup_age_minutes,omitempty"`
	RPOBreached    bool     `json:"rpo_breached"`
	RecordingsDir  string   `json:"recordings_dir"`
	GeneratedAt    time.Time `json:"generated_at"`
	RunbookHint    string   `json:"runbook_hint"`
}

func (s *Service) GetSettings(ctx context.Context) (Settings, error) {
	var st Settings
	var drillOK *bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT site_name, role, rpo_minutes, rto_minutes, replica_dsn_hint, backup_dir,
			last_backup_at, last_backup_path, last_backup_bytes, last_backup_status,
			last_drill_at, last_drill_notes, last_drill_ok, updated_at
		FROM dr_settings WHERE id=1`).Scan(
		&st.SiteName, &st.Role, &st.RPOMinutes, &st.RTOMinutes, &st.ReplicaDSNHint, &st.BackupDir,
		&st.LastBackupAt, &st.LastBackupPath, &st.LastBackupBytes, &st.LastBackupStatus,
		&st.LastDrillAt, &st.LastDrillNotes, &drillOK, &st.UpdatedAt)
	st.LastDrillOK = drillOK
	return st, err
}

func (s *Service) PutSettings(ctx context.Context, actorID uuid.UUID, in SettingsInput, ip, ua string) (Settings, error) {
	cur, err := s.GetSettings(ctx)
	if err != nil {
		return Settings{}, err
	}
	if in.SiteName != nil {
		cur.SiteName = strings.TrimSpace(*in.SiteName)
	}
	if in.Role != nil {
		switch *in.Role {
		case "primary", "dr", "standalone":
			cur.Role = *in.Role
		default:
			return Settings{}, fmt.Errorf("invalid role")
		}
	}
	if in.RPOMinutes != nil {
		if *in.RPOMinutes <= 0 {
			return Settings{}, fmt.Errorf("rpo_minutes must be > 0")
		}
		cur.RPOMinutes = *in.RPOMinutes
	}
	if in.RTOMinutes != nil {
		if *in.RTOMinutes <= 0 {
			return Settings{}, fmt.Errorf("rto_minutes must be > 0")
		}
		cur.RTOMinutes = *in.RTOMinutes
	}
	if in.ReplicaDSNHint != nil {
		cur.ReplicaDSNHint = strings.TrimSpace(*in.ReplicaDSNHint)
	}
	if in.BackupDir != nil {
		cur.BackupDir = strings.TrimSpace(*in.BackupDir)
		if cur.BackupDir == "" {
			cur.BackupDir = "/tmp/keeppam-backups"
		}
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE dr_settings SET site_name=$1, role=$2, rpo_minutes=$3, rto_minutes=$4,
			replica_dsn_hint=$5, backup_dir=$6, updated_at=NOW() WHERE id=1`,
		cur.SiteName, cur.Role, cur.RPOMinutes, cur.RTOMinutes, cur.ReplicaDSNHint, cur.BackupDir)
	if err != nil {
		return Settings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "dr.settings.updated", "dr_settings", "1", ip, ua, map[string]any{
		"role": cur.Role, "rpo": cur.RPOMinutes, "rto": cur.RTOMinutes,
	})
	return s.GetSettings(ctx)
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	st, err := s.GetSettings(ctx)
	if err != nil {
		return Status{}, err
	}
	out := Status{
		Settings: st, PrimaryOK: true, RecordingsDir: s.recordingsDir,
		GeneratedAt: time.Now().UTC(),
		RunbookHint: "docs/dr-runbook.txt · scripts/backup.sh · scripts/restore.sh",
	}
	if err := s.db.Pool.Ping(ctx); err != nil {
		out.PrimaryOK = false
	}
	if hint := strings.TrimSpace(st.ReplicaDSNHint); hint != "" && looksLikeDSN(hint) {
		ok := false
		pool, err := pgxpool.New(ctx, hint)
		if err != nil {
			out.ReplicaError = err.Error()
		} else {
			defer pool.Close()
			if err := pool.Ping(ctx); err != nil {
				out.ReplicaError = err.Error()
			} else {
				ok = true
			}
		}
		out.ReplicaOK = &ok
	}
	if st.LastBackupAt != nil {
		age := int(time.Since(*st.LastBackupAt).Minutes())
		out.BackupAgeMin = &age
		out.BackupFresh = age <= st.RPOMinutes
		out.RPOBreached = age > st.RPOMinutes
	} else {
		out.RPOBreached = true
		out.BackupFresh = false
	}
	return out, nil
}

func looksLikeDSN(s string) bool {
	return strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://")
}

type BackupResult struct {
	Path   string    `json:"path"`
	Bytes  int64     `json:"bytes"`
	Status string    `json:"status"`
	At     time.Time `json:"at"`
}

func (s *Service) RunBackup(ctx context.Context, actorID uuid.UUID, ip, ua string) (BackupResult, error) {
	st, err := s.GetSettings(ctx)
	if err != nil {
		return BackupResult{}, err
	}
	dir := st.BackupDir
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return BackupResult{}, err
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	base := filepath.Join(dir, "keeppam-"+ts)
	sqlPath := base + "-db.sql"
	recPath := base + "-recordings.tar.gz"
	bundle := base + ".meta"

	// pg_dump if available
	dumpErr := ""
	if _, err := exec.LookPath("pg_dump"); err == nil && s.databaseURL != "" {
		cmd := exec.CommandContext(ctx, "pg_dump", "--no-owner", "--no-acl", "-f", sqlPath, s.databaseURL)
		if out, err := cmd.CombinedOutput(); err != nil {
			dumpErr = fmt.Sprintf("pg_dump: %v (%s)", err, truncate(string(out), 200))
		}
	} else {
		// fallback: copy schema-less note
		dumpErr = "pg_dump not in PATH — use scripts/backup.sh on host"
		_ = os.WriteFile(sqlPath+".txt", []byte(dumpErr+"\nDATABASE_URL configured in API\n"), 0o640)
	}

	// recordings archive
	recErr := ""
	if _, err := exec.LookPath("tar"); err == nil {
		cmd := exec.CommandContext(ctx, "tar", "-czf", recPath, "-C", filepath.Dir(s.recordingsDir), filepath.Base(s.recordingsDir))
		if s.recordingsDir == "" || s.recordingsDir == "." {
			cmd = exec.CommandContext(ctx, "tar", "-czf", recPath, "-C", ".", ".")
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			recErr = fmt.Sprintf("tar: %v (%s)", err, truncate(string(out), 200))
		}
	} else {
		recErr = "tar not available"
	}

	var total int64
	for _, p := range []string{sqlPath, sqlPath + ".txt", recPath} {
		if fi, err := os.Stat(p); err == nil {
			total += fi.Size()
		}
	}
	status := "ok"
	if dumpErr != "" || recErr != "" {
		status = "partial"
		if dumpErr != "" && recErr != "" {
			status = "failed"
		}
	}
	meta := fmt.Sprintf("at=%s status=%s dump_err=%q rec_err=%q bytes=%d\n", ts, status, dumpErr, recErr, total)
	_ = os.WriteFile(bundle, []byte(meta), 0o640)

	now := time.Now().UTC()
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE dr_settings SET last_backup_at=$1, last_backup_path=$2, last_backup_bytes=$3, last_backup_status=$4, updated_at=NOW()
		WHERE id=1`, now, base, total, status)
	_ = s.aud.Record(ctx, &actorID, "dr.backup.completed", "dr_settings", "1", ip, ua, map[string]any{
		"path": base, "bytes": total, "status": status, "dump_err": dumpErr, "rec_err": recErr,
	})
	return BackupResult{Path: base, Bytes: total, Status: status, At: now}, nil
}

type DrillInput struct {
	OK    bool   `json:"ok"`
	Notes string `json:"notes"`
}

func (s *Service) RecordDrill(ctx context.Context, actorID uuid.UUID, in DrillInput, ip, ua string) (Settings, error) {
	now := time.Now().UTC()
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE dr_settings SET last_drill_at=$1, last_drill_notes=$2, last_drill_ok=$3, updated_at=NOW() WHERE id=1`,
		now, strings.TrimSpace(in.Notes), in.OK)
	if err != nil {
		return Settings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "dr.drill.recorded", "dr_settings", "1", ip, ua, map[string]any{
		"ok": in.OK, "notes": strings.TrimSpace(in.Notes),
	})
	return s.GetSettings(ctx)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
