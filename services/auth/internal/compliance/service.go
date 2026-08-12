package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/recstore"
	"github.com/keeppam/auth/internal/store"
)

var ErrNotFound = errors.New("not found")

type Service struct {
	db            *store.DB
	aud           *audit.Service
	recordingsDir string
	store         recstore.Store
	dataKeySource string
}

func New(db *store.DB, aud *audit.Service, recordingsDir string, store recstore.Store, dataKeySource string) *Service {
	if store == nil {
		store = &recstore.Local{Root: recordingsDir}
	}
	return &Service{db: db, aud: aud, recordingsDir: recordingsDir, store: store, dataKeySource: dataKeySource}
}

type RetentionPolicy struct {
	ID                     uuid.UUID `json:"id"`
	Name                   string    `json:"name"`
	AuditRetentionDays     int       `json:"audit_retention_days"`
	SessionRetentionDays   int       `json:"session_retention_days"`
	RecordingRetentionDays int       `json:"recording_retention_days"`
	PurgeEnabled           bool      `json:"purge_enabled"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type RetentionInput struct {
	AuditRetentionDays     *int  `json:"audit_retention_days"`
	SessionRetentionDays   *int  `json:"session_retention_days"`
	RecordingRetentionDays *int  `json:"recording_retention_days"`
	PurgeEnabled           *bool `json:"purge_enabled"`
}

type Pack struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	Controls      []string `json:"controls"`
	AuditDays     int      `json:"audit_days"`
	SessionDays   int      `json:"session_days"`
	RecordingDays int      `json:"recording_days"`
	Active        bool     `json:"active"`
}

type LegalHold struct {
	ID           uuid.UUID  `json:"id"`
	ResourceType string     `json:"resource_type"`
	ResourceID   string     `json:"resource_id"`
	Reason       string     `json:"reason"`
	Active       bool       `json:"active"`
	CreatedAt    time.Time  `json:"created_at"`
	ReleasedAt   *time.Time `json:"released_at,omitempty"`
}

type ControlResult struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"` // pass|fail|warn
	Detail string `json:"detail"`
}

type Status struct {
	ActivePackID   string          `json:"active_pack_id,omitempty"`
	AppliedAt      *time.Time      `json:"applied_at,omitempty"`
	Retention      RetentionPolicy `json:"retention"`
	Controls       []ControlResult `json:"controls"`
	LegalHoldCount int             `json:"legal_hold_count"`
	LastPurgeAt    *time.Time      `json:"last_purge_at,omitempty"`
	LastPurgeStats map[string]any  `json:"last_purge_stats,omitempty"`
	GeneratedAt    time.Time       `json:"generated_at"`
}

func (s *Service) GetRetention(ctx context.Context) (RetentionPolicy, error) {
	var p RetentionPolicy
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, audit_retention_days, session_retention_days, recording_retention_days, purge_enabled, updated_at
		FROM retention_policies WHERE name='default'`).Scan(
		&p.ID, &p.Name, &p.AuditRetentionDays, &p.SessionRetentionDays, &p.RecordingRetentionDays, &p.PurgeEnabled, &p.UpdatedAt)
	return p, err
}

func (s *Service) PutRetention(ctx context.Context, actorID uuid.UUID, in RetentionInput, ip, ua string) (RetentionPolicy, error) {
	cur, err := s.GetRetention(ctx)
	if err != nil {
		return RetentionPolicy{}, err
	}
	if in.AuditRetentionDays != nil {
		cur.AuditRetentionDays = *in.AuditRetentionDays
	}
	if in.SessionRetentionDays != nil {
		cur.SessionRetentionDays = *in.SessionRetentionDays
	}
	if in.RecordingRetentionDays != nil {
		cur.RecordingRetentionDays = *in.RecordingRetentionDays
	}
	if in.PurgeEnabled != nil {
		cur.PurgeEnabled = *in.PurgeEnabled
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE retention_policies SET
			audit_retention_days=$2, session_retention_days=$3, recording_retention_days=$4,
			purge_enabled=$5, updated_at=NOW(), updated_by=$6
		WHERE id=$1`,
		cur.ID, cur.AuditRetentionDays, cur.SessionRetentionDays, cur.RecordingRetentionDays, cur.PurgeEnabled, actorID)
	if err != nil {
		return RetentionPolicy{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "compliance.retention.updated", "retention_policy", cur.ID.String(), ip, ua, map[string]any{
		"audit_days": cur.AuditRetentionDays, "session_days": cur.SessionRetentionDays,
		"recording_days": cur.RecordingRetentionDays, "purge_enabled": cur.PurgeEnabled,
	})
	return s.GetRetention(ctx)
}

func (s *Service) ListPacks(ctx context.Context) ([]Pack, error) {
	var active string
	_ = s.db.Pool.QueryRow(ctx, `SELECT COALESCE(active_pack_id,'') FROM compliance_state LIMIT 1`).Scan(&active)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, title, description, controls, audit_days, session_days, recording_days
		FROM compliance_packs ORDER BY sort_order, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Pack
	for rows.Next() {
		var p Pack
		var raw []byte
		if err := rows.Scan(&p.ID, &p.Title, &p.Description, &raw, &p.AuditDays, &p.SessionDays, &p.RecordingDays); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(raw, &p.Controls)
		if p.Controls == nil {
			p.Controls = []string{}
		}
		p.Active = p.ID == active
		out = append(out, p)
	}
	if out == nil {
		out = []Pack{}
	}
	return out, rows.Err()
}

func (s *Service) ApplyPack(ctx context.Context, actorID uuid.UUID, packID, ip, ua string) (Pack, error) {
	var p Pack
	var raw []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, title, description, controls, audit_days, session_days, recording_days
		FROM compliance_packs WHERE id=$1`, packID).Scan(
		&p.ID, &p.Title, &p.Description, &raw, &p.AuditDays, &p.SessionDays, &p.RecordingDays)
	if errors.Is(err, pgx.ErrNoRows) {
		return Pack{}, ErrNotFound
	}
	if err != nil {
		return Pack{}, err
	}
	_ = json.Unmarshal(raw, &p.Controls)
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE retention_policies SET
			audit_retention_days=$1, session_retention_days=$2, recording_retention_days=$3,
			purge_enabled=TRUE, updated_at=NOW(), updated_by=$4
		WHERE name='default'`, p.AuditDays, p.SessionDays, p.RecordingDays, actorID)
	if err != nil {
		return Pack{}, err
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE compliance_state SET active_pack_id=$1, applied_at=NOW(), applied_by=$2, updated_at=NOW()`,
		packID, actorID)
	if err != nil {
		return Pack{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "compliance.pack.applied", "compliance_pack", packID, ip, ua, map[string]any{
		"audit_days": p.AuditDays, "session_days": p.SessionDays, "recording_days": p.RecordingDays,
	})
	p.Active = true
	return p, nil
}

func (s *Service) ListHolds(ctx context.Context, activeOnly bool) ([]LegalHold, error) {
	q := `SELECT id, resource_type, resource_id, reason, active, created_at, released_at FROM legal_holds`
	if activeOnly {
		q += ` WHERE active=TRUE`
	}
	q += ` ORDER BY created_at DESC LIMIT 200`
	rows, err := s.db.Pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LegalHold
	for rows.Next() {
		var h LegalHold
		if err := rows.Scan(&h.ID, &h.ResourceType, &h.ResourceID, &h.Reason, &h.Active, &h.CreatedAt, &h.ReleasedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	if out == nil {
		out = []LegalHold{}
	}
	return out, rows.Err()
}

type CreateHoldInput struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Reason       string `json:"reason"`
}

func (s *Service) CreateHold(ctx context.Context, actorID uuid.UUID, in CreateHoldInput, ip, ua string) (LegalHold, error) {
	in.ResourceType = strings.TrimSpace(in.ResourceType)
	switch in.ResourceType {
	case "session", "asset", "user", "global":
	default:
		return LegalHold{}, fmt.Errorf("invalid resource_type")
	}
	if in.ResourceType != "global" && strings.TrimSpace(in.ResourceID) == "" {
		return LegalHold{}, fmt.Errorf("resource_id required")
	}
	id := store.NewID()
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO legal_holds (id, resource_type, resource_id, reason, active, created_at, created_by)
		VALUES ($1,$2,$3,$4,TRUE,NOW(),$5)`,
		id, in.ResourceType, strings.TrimSpace(in.ResourceID), strings.TrimSpace(in.Reason), actorID)
	if err != nil {
		return LegalHold{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "compliance.legal_hold.created", "legal_hold", id.String(), ip, ua, map[string]any{
		"resource_type": in.ResourceType, "resource_id": in.ResourceID,
	})
	if in.ResourceType == "session" {
		s.applySessionLegalHold(ctx, strings.TrimSpace(in.ResourceID), true)
	}
	return s.getHold(ctx, id)
}

func (s *Service) ReleaseHold(ctx context.Context, actorID, holdID uuid.UUID, ip, ua string) (LegalHold, error) {
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE legal_holds SET active=FALSE, released_at=NOW(), released_by=$2
		WHERE id=$1 AND active=TRUE`, holdID, actorID)
	if err != nil {
		return LegalHold{}, err
	}
	if tag.RowsAffected() == 0 {
		return LegalHold{}, ErrNotFound
	}
	hold, err := s.getHold(ctx, holdID)
	if err != nil {
		return LegalHold{}, err
	}
	if hold.ResourceType == "session" {
		s.applySessionLegalHold(ctx, hold.ResourceID, false)
	}
	_ = s.aud.Record(ctx, &actorID, "compliance.legal_hold.released", "legal_hold", holdID.String(), ip, ua, nil)
	return hold, nil
}

func (s *Service) getHold(ctx context.Context, id uuid.UUID) (LegalHold, error) {
	var h LegalHold
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, resource_type, resource_id, reason, active, created_at, released_at
		FROM legal_holds WHERE id=$1`, id).Scan(
		&h.ID, &h.ResourceType, &h.ResourceID, &h.Reason, &h.Active, &h.CreatedAt, &h.ReleasedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return LegalHold{}, ErrNotFound
	}
	return h, err
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	ret, err := s.GetRetention(ctx)
	if err != nil {
		return Status{}, err
	}
	st := Status{Retention: ret, GeneratedAt: time.Now().UTC(), Controls: []ControlResult{}, LastPurgeStats: map[string]any{}}
	var packID *string
	var applied, lastPurge *time.Time
	var stats []byte
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT active_pack_id, applied_at, last_purge_at, last_purge_stats FROM compliance_state LIMIT 1`).Scan(
		&packID, &applied, &lastPurge, &stats)
	if packID != nil {
		st.ActivePackID = *packID
	}
	st.AppliedAt = applied
	st.LastPurgeAt = lastPurge
	if len(stats) > 0 {
		_ = json.Unmarshal(stats, &st.LastPurgeStats)
	}
	_ = s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM legal_holds WHERE active=TRUE`).Scan(&st.LegalHoldCount)

	st.Controls = append(st.Controls, s.checkMFAAdmins(ctx))
	st.Controls = append(st.Controls, s.checkSIEM(ctx))
	st.Controls = append(st.Controls, s.checkRetention(ret))
	st.Controls = append(st.Controls, s.checkRecordings(ctx))
	st.Controls = append(st.Controls, s.checkJIT(ctx))
	st.Controls = append(st.Controls, s.checkABAC(ctx))
	st.Controls = append(st.Controls, ControlResult{
		ID: "legal_hold", Title: "Legal hold",
		Status: ternary(st.LegalHoldCount >= 0, "pass", "fail"),
		Detail: fmt.Sprintf("активных holds: %d", st.LegalHoldCount),
	})
	st.Controls = append(st.Controls, s.checkAudit(ctx))
	st.Controls = append(st.Controls, s.checkWORM())
	st.Controls = append(st.Controls, s.checkKMSHSM())
	return st, nil
}

func (s *Service) checkMFAAdmins(ctx context.Context) ControlResult {
	var total, withMFA int
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT u.id),
			COUNT(DISTINCT u.id) FILTER (WHERE u.mfa_enabled)
		FROM users u
		JOIN user_role_bindings urb ON urb.user_id = u.id
		JOIN roles r ON r.id = urb.role_id
		WHERE r.name='admin' AND u.status='active'`).Scan(&total, &withMFA)
	if total == 0 {
		return ControlResult{ID: "mfa_admins", Title: "MFA у admin", Status: "warn", Detail: "нет активных admin"}
	}
	if withMFA < total {
		return ControlResult{ID: "mfa_admins", Title: "MFA у admin", Status: "fail",
			Detail: fmt.Sprintf("%d/%d admin с MFA", withMFA, total)}
	}
	return ControlResult{ID: "mfa_admins", Title: "MFA у admin", Status: "pass", Detail: fmt.Sprintf("%d/%d", withMFA, total)}
}

func (s *Service) checkSIEM(ctx context.Context) ControlResult {
	var enabled bool
	err := s.db.Pool.QueryRow(ctx, `SELECT enabled FROM siem_settings WHERE id=1`).Scan(&enabled)
	if err != nil {
		return ControlResult{ID: "siem_export", Title: "SIEM export", Status: "warn", Detail: "настройки SIEM недоступны"}
	}
	if !enabled {
		return ControlResult{ID: "siem_export", Title: "SIEM export", Status: "fail", Detail: "выключен"}
	}
	return ControlResult{ID: "siem_export", Title: "SIEM export", Status: "pass", Detail: "включён"}
}

func (s *Service) checkRetention(ret RetentionPolicy) ControlResult {
	if ret.AuditRetentionDays <= 0 && ret.SessionRetentionDays <= 0 && ret.RecordingRetentionDays <= 0 {
		return ControlResult{ID: "retention_configured", Title: "Retention", Status: "fail", Detail: "все TTL = 0"}
	}
	return ControlResult{ID: "retention_configured", Title: "Retention", Status: "pass",
		Detail: fmt.Sprintf("audit=%dd session=%dd recording=%dd purge=%v",
			ret.AuditRetentionDays, ret.SessionRetentionDays, ret.RecordingRetentionDays, ret.PurgeEnabled)}
}

func (s *Service) checkRecordings(ctx context.Context) ControlResult {
	var n int
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions
		WHERE recording_path <> '' AND status IN ('ended','failed','active')`).Scan(&n)
	return ControlResult{ID: "session_recording", Title: "Session recording", Status: "pass",
		Detail: fmt.Sprintf("сессий с recording_path: %d", n)}
}

func (s *Service) checkJIT(ctx context.Context) ControlResult {
	var n int
	_ = s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM access_requests`).Scan(&n)
	return ControlResult{ID: "jit_approvals", Title: "JIT / approvals", Status: "pass",
		Detail: fmt.Sprintf("access_requests: %d", n)}
}

func (s *Service) checkABAC(ctx context.Context) ControlResult {
	var n int
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM asset_access_bindings
		WHERE COALESCE(cardinality(required_tags),0) > 0 OR require_ticket
		   OR COALESCE(require_reason,false) OR COALESCE(cardinality(allowed_cidrs),0) > 0`).Scan(&n)
	st := "warn"
	if n > 0 {
		st = "pass"
	}
	return ControlResult{ID: "abac_tags", Title: "ABAC tags/ticket/CIDR", Status: st,
		Detail: fmt.Sprintf("bindings с ABAC-условиями: %d", n)}
}

func (s *Service) checkAudit(ctx context.Context) ControlResult {
	var n int
	_ = s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&n)
	if n == 0 {
		return ControlResult{ID: "audit_trail", Title: "Audit trail", Status: "fail", Detail: "пусто"}
	}
	return ControlResult{ID: "audit_trail", Title: "Audit trail", Status: "pass", Detail: fmt.Sprintf("events: %d", n)}
}

func (s *Service) checkWORM() ControlResult {
	backend := "local"
	mode := ""
	days := 0
	if s.store != nil {
		backend = s.store.Backend()
		mode = s.store.ObjectLockMode()
		days = s.store.ObjectLockDays()
	}
	if backend != "s3" {
		return ControlResult{ID: "worm_recordings", Title: "WORM recordings (S3 Object Lock)", Status: "warn",
			Detail: "backend=local — Object Lock недоступен"}
	}
	if mode == "" {
		return ControlResult{ID: "worm_recordings", Title: "WORM recordings (S3 Object Lock)", Status: "fail",
			Detail: "S3 без Object Lock (KEEPPAM_S3_OBJECT_LOCK_MODE)"}
	}
	return ControlResult{ID: "worm_recordings", Title: "WORM recordings (S3 Object Lock)", Status: "pass",
		Detail: fmt.Sprintf("%s · %d days", mode, days)}
}

func (s *Service) checkKMSHSM() ControlResult {
	src := strings.ToLower(strings.TrimSpace(s.dataKeySource))
	switch src {
	case "vault":
		return ControlResult{ID: "kms_hsm_key", Title: "KMS/HSM data key", Status: "pass",
			Detail: "Vault Transit (HSM-backed Vault снаружи)"}
	case "file":
		return ControlResult{ID: "kms_hsm_key", Title: "KMS/HSM data key", Status: "warn",
			Detail: "file provider — лучше Vault/HSM"}
	default:
		return ControlResult{ID: "kms_hsm_key", Title: "KMS/HSM data key", Status: "fail",
			Detail: "env data key — не для prod"}
	}
}

func ternary(ok bool, a, b string) string {
	if ok {
		return a
	}
	return b
}

type PurgeStats struct {
	RecordingsRemoved int    `json:"recordings_removed"`
	SessionsPurged    int    `json:"sessions_purged"`
	SkippedHolds      int    `json:"skipped_holds"`
	SkippedWORM       int    `json:"skipped_worm"`
	AuditNote         string `json:"audit_note"`
}

func (s *Service) Purge(ctx context.Context) (PurgeStats, error) {
	ret, err := s.GetRetention(ctx)
	if err != nil {
		return PurgeStats{}, err
	}
	stats := PurgeStats{AuditNote: "audit_events не удаляются (WORM/append-only)"}
	if !ret.PurgeEnabled {
		stats.AuditNote = "purge_enabled=false"
		_ = s.savePurgeStats(ctx, stats)
		return stats, nil
	}

	heldSessions := map[string]bool{}
	heldAssets := map[string]bool{}
	heldUsers := map[string]bool{}
	globalHold := false
	holds, _ := s.ListHolds(ctx, true)
	for _, h := range holds {
		switch h.ResourceType {
		case "global":
			globalHold = true
		case "session":
			heldSessions[h.ResourceID] = true
		case "asset":
			heldAssets[h.ResourceID] = true
		case "user":
			heldUsers[h.ResourceID] = true
		}
	}
	if globalHold {
		stats.SkippedHolds = len(holds)
		stats.AuditNote = "global legal hold — purge пропущен"
		_ = s.savePurgeStats(ctx, stats)
		return stats, nil
	}

	if ret.RecordingRetentionDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -ret.RecordingRetentionDays)
		rows, err := s.db.Pool.Query(ctx, `
			SELECT id, user_id, asset_id, recording_path FROM sessions
			WHERE status IN ('ended','failed')
			  AND COALESCE(ended_at, created_at) < $1
			  AND recording_path <> ''`, cutoff)
		if err != nil {
			return stats, err
		}
		type rowT struct {
			id, userID, assetID uuid.UUID
			path                string
		}
		var list []rowT
		for rows.Next() {
			var r rowT
			if err := rows.Scan(&r.id, &r.userID, &r.assetID, &r.path); err != nil {
				rows.Close()
				return stats, err
			}
			list = append(list, r)
		}
		rows.Close()
		for _, r := range list {
			if heldSessions[r.id.String()] || heldAssets[r.assetID.String()] || heldUsers[r.userID.String()] {
				stats.SkippedHolds++
				continue
			}
			deleted, worm, err := s.store.TryDelete(ctx, r.path)
			if worm {
				stats.SkippedWORM++
				continue
			}
			if err == nil && deleted {
				_, _ = s.db.Pool.Exec(ctx, `UPDATE sessions SET recording_path='' WHERE id=$1`, r.id)
				stats.RecordingsRemoved++
			}
		}
	}

	if ret.SessionRetentionDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -ret.SessionRetentionDays)
		rows, err := s.db.Pool.Query(ctx, `
			SELECT id, user_id, asset_id FROM sessions
			WHERE status IN ('ended','failed')
			  AND COALESCE(ended_at, created_at) < $1`, cutoff)
		if err != nil {
			return stats, err
		}
		defer rows.Close()
		for rows.Next() {
			var id, userID, assetID uuid.UUID
			if err := rows.Scan(&id, &userID, &assetID); err != nil {
				return stats, err
			}
			if heldSessions[id.String()] || heldAssets[assetID.String()] || heldUsers[userID.String()] {
				stats.SkippedHolds++
				continue
			}
			_, _ = s.db.Pool.Exec(ctx, `DELETE FROM session_events WHERE session_id=$1`, id)
			tag, err := s.db.Pool.Exec(ctx, `DELETE FROM sessions WHERE id=$1`, id)
			if err == nil && tag.RowsAffected() > 0 {
				stats.SessionsPurged++
			}
		}
	}

	_ = s.savePurgeStats(ctx, stats)
	return stats, nil
}

func (s *Service) savePurgeStats(ctx context.Context, stats PurgeStats) error {
	b, _ := json.Marshal(stats)
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE compliance_state SET last_purge_at=NOW(), last_purge_stats=$1, updated_at=NOW()`, b)
	return err
}

func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	_, _ = s.Purge(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.Purge(ctx)
		}
	}
}

func (s *Service) applySessionLegalHold(ctx context.Context, sessionID string, on bool) {
	id, err := uuid.Parse(sessionID)
	if err != nil || s.store == nil {
		return
	}
	var path string
	if err := s.db.Pool.QueryRow(ctx, `SELECT COALESCE(recording_path,'') FROM sessions WHERE id=$1`, id).Scan(&path); err != nil || path == "" {
		return
	}
	_ = s.store.SetLegalHold(ctx, path, on)
}

func removeRecording(path string) error {
	if path == "" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return os.RemoveAll(path)
	}
	if fi.IsDir() {
		return os.RemoveAll(path)
	}
	_ = os.Remove(path)
	_ = os.Remove(strings.TrimSuffix(path, filepath.Ext(path)) + ".jsonl")
	return nil
}
