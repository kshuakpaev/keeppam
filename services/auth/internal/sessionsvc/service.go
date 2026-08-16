package sessionsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/obs"
	"github.com/keeppam/auth/internal/recstore"
	"github.com/keeppam/auth/internal/store"
)

type Session struct {
	ID            uuid.UUID  `json:"id"`
	UserID        uuid.UUID  `json:"user_id"`
	AssetID       uuid.UUID  `json:"asset_id"`
	AccountID     uuid.UUID  `json:"account_id"`
	Protocol      string     `json:"protocol"`
	Status        string     `json:"status"`
	ClientIP      string     `json:"client_ip"`
	RecordingPath string     `json:"recording_path,omitempty"`
	ErrorMessage  string     `json:"error_message,omitempty"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	TicketID        string     `json:"ticket_id,omitempty"`
	Reason          string     `json:"reason,omitempty"`
	DBPrivilege     string     `json:"db_privilege,omitempty"`
	DatabaseName    string     `json:"database_name,omitempty"`
	SQLPolicyPackID *uuid.UUID `json:"sql_policy_pack_id,omitempty"`
	HTTPPolicyPackID *uuid.UUID `json:"http_policy_pack_id,omitempty"`
	K8sNamespaces   []string   `json:"k8s_namespaces,omitempty"`
	BreakGlass      bool       `json:"break_glass"`
	// Joined fields for UI
	Username        string `json:"username,omitempty"`
	AssetName       string `json:"asset_name,omitempty"`
	AccountUsername string `json:"account_username,omitempty"`
	AssetAddress    string `json:"asset_address,omitempty"`
	HasRecording    bool   `json:"has_recording"`
	Isolated        bool   `json:"isolated"`
}

type Service struct {
	db            *store.DB
	aud           *audit.Service
	recordingsDir string
	store         recstore.Store
	endHook       EndHook
}

// EndHook runs after a session is marked ended/failed (best-effort cleanup).
type EndHook func(ctx context.Context, id uuid.UUID, protocol string)

func New(db *store.DB, aud *audit.Service, recordingsDir string) *Service {
	_ = os.MkdirAll(recordingsDir, 0o750)
	return &Service{db: db, aud: aud, recordingsDir: recordingsDir, store: &recstore.Local{Root: recordingsDir}}
}

func (s *Service) SetEndHook(h EndHook) {
	s.endHook = h
}

func (s *Service) SetRecordingStore(st recstore.Store) {
	if st != nil {
		s.store = st
	}
}

func (s *Service) RecordingStore() recstore.Store { return s.store }

func (s *Service) RecordingsDir() string { return s.recordingsDir }

func (s *Service) syncRecording(ctx context.Context, id uuid.UUID) {
	if s.store == nil {
		return
	}
	sess, err := s.Get(ctx, id)
	if err != nil || sess.RecordingPath == "" {
		return
	}
	_ = s.store.Sync(ctx, sess.RecordingPath)
}

type CreateInput struct {
	AssetID     uuid.UUID
	AccountID   uuid.UUID
	Protocol    string
	ClientIP    string
	TicketID    string
	Reason      string
	DBPrivilege  string // readonly|readwrite for postgres/mysql
	DatabaseName    string     // target database/schema name
	SQLPolicyPackID *uuid.UUID // optional SQL JEA pack snapshot
	HTTPPolicyPackID *uuid.UUID // optional HTTP/URL ACL pack snapshot
	K8sNamespaces   []string
	Isolated        bool       // https isolated Chromium via VNC
	BreakGlass      bool
}

type ListFilter struct {
	OnlyUser *uuid.UUID
	Status   string
	Protocol string
	Q        string
	Limit    int
	Offset   int
}

func (s *Service) Create(ctx context.Context, userID uuid.UUID, in CreateInput, ua string) (Session, error) {
	if in.Protocol == "" {
		in.Protocol = "ssh"
	}
	id := store.NewID()
	now := time.Now().UTC()
	recPath := filepath.Join(s.recordingsDir, id.String()+".cast")
	if in.Protocol == "rdp" || in.Protocol == "vnc" {
		recPath = filepath.Join(s.recordingsDir, "guac", id.String())
	}
	if in.Protocol == "postgres" || in.Protocol == "mysql" {
		recPath = filepath.Join(s.recordingsDir, "sql", id.String()+".jsonl")
	}
	if in.Protocol == "https" {
		if in.Isolated {
			recPath = filepath.Join(s.recordingsDir, "guac", id.String())
		} else {
			recPath = filepath.Join(s.recordingsDir, "http", id.String()+".jsonl")
		}
	}
	if in.Protocol == "kubectl" {
		recPath = filepath.Join(s.recordingsDir, "k8s", id.String()+".jsonl")
	}
	dbPriv := "readonly"
	if in.Protocol == "postgres" || in.Protocol == "mysql" {
		if in.DBPrivilege == "readwrite" {
			dbPriv = "readwrite"
		}
	} else {
		dbPriv = ""
	}
	dbName := strings.TrimSpace(in.DatabaseName)
	if dbName == "" && in.Protocol == "postgres" {
		dbName = "postgres"
	}
	ns := in.K8sNamespaces
	if ns == nil {
		ns = []string{}
	}
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, asset_id, account_id, protocol, status, client_ip, recording_path, ticket_id, reason, db_privilege, database_name, sql_policy_pack_id, http_policy_pack_id, k8s_namespaces, break_glass, created_at)
		VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		id, userID, in.AssetID, in.AccountID, in.Protocol, in.ClientIP, recPath,
		strings.TrimSpace(in.TicketID), strings.TrimSpace(in.Reason), dbPriv, dbName, in.SQLPolicyPackID, in.HTTPPolicyPackID, ns, in.BreakGlass, now)
	if err != nil {
		return Session{}, err
	}
	_ = s.aud.Record(ctx, &userID, "session.created", "session", id.String(), in.ClientIP, ua, map[string]any{
		"asset_id": in.AssetID.String(), "account_id": in.AccountID.String(), "protocol": in.Protocol,
		"ticket_id": strings.TrimSpace(in.TicketID), "break_glass": in.BreakGlass,
	})
	_ = s.AddEvent(ctx, id, "created", map[string]any{"protocol": in.Protocol})
	return s.Get(ctx, id)
}

func (s *Service) MarkActive(ctx context.Context, id uuid.UUID) error {
	row, _ := s.Get(ctx, id)
	now := time.Now().UTC()
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE sessions SET status='active', started_at=$2, last_seen_at=$2 WHERE id=$1`, id, now)
	if err != nil {
		return err
	}
	if row.Status == "pending" {
		obs.Default.ObserveSessionSetup(now.Sub(row.CreatedAt))
	}
	return s.AddEvent(ctx, id, "started", nil)
}

func (s *Service) Touch(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE sessions SET last_seen_at=NOW() WHERE id=$1 AND status='active'`, id)
	return err
}

func (s *Service) MarkEnded(ctx context.Context, id uuid.UUID, failMsg string) error {
	var protocol string
	_ = s.db.Pool.QueryRow(ctx, `SELECT protocol FROM sessions WHERE id=$1`, id).Scan(&protocol)
	now := time.Now().UTC()
	status := "ended"
	if failMsg != "" {
		status = "failed"
	}
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE sessions SET status=$2, ended_at=$3, error_message=$4 WHERE id=$1`,
		id, status, now, failMsg)
	if err != nil {
		return err
	}
	_ = s.AddEvent(ctx, id, status, map[string]any{"error": failMsg})
	if s.endHook != nil {
		s.endHook(ctx, id, protocol)
	}
	s.syncRecording(ctx, id)
	return nil
}

// CloseStale ends active sessions with no heartbeat within olderThan.
func (s *Service) CloseStale(ctx context.Context, olderThan time.Duration) (int, error) {
	if olderThan <= 0 {
		olderThan = 2 * time.Minute
	}
	cutoff := time.Now().UTC().Add(-olderThan)
	rows, err := s.db.Pool.Query(ctx, `
		UPDATE sessions
		SET status='ended', ended_at=NOW(), error_message='stale: no heartbeat'
		WHERE status='active'
		  AND COALESCE(last_seen_at, started_at, created_at) < $1
		RETURNING id, protocol`, cutoff)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id uuid.UUID
		var protocol string
		if err := rows.Scan(&id, &protocol); err != nil {
			return n, err
		}
		_ = s.AddEvent(ctx, id, "ended", map[string]any{"error": "stale: no heartbeat"})
		if s.endHook != nil {
			s.endHook(ctx, id, protocol)
		}
		s.syncRecording(ctx, id)
		n++
	}
	return n, rows.Err()
}

func (s *Service) AddEvent(ctx context.Context, sessionID uuid.UUID, eventType string, payload map[string]any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	b, _ := json.Marshal(payload)
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO session_events (id, session_id, ts, event_type, payload)
		VALUES ($1,$2,NOW(),$3,$4)`, store.NewID(), sessionID, eventType, b)
	return err
}

type SessionEvent struct {
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
	TS      time.Time      `json:"ts"`
}

func (s *Service) ListEvents(ctx context.Context, sessionID uuid.UUID, limit int) ([]SessionEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT event_type, payload, ts FROM session_events
		WHERE session_id=$1 ORDER BY ts DESC LIMIT $2`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionEvent
	for rows.Next() {
		var e SessionEvent
		var raw []byte
		if err := rows.Scan(&e.Type, &raw, &e.TS); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(raw, &e.Payload)
		if e.Payload == nil {
			e.Payload = map[string]any{}
		}
		out = append(out, e)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}

const sessionSelect = `
		SELECT s.id, s.user_id, s.asset_id, s.account_id, s.protocol, s.status, s.client_ip,
			s.recording_path, s.error_message, s.started_at, s.ended_at, s.last_seen_at, s.created_at,
			s.ticket_id, s.reason, COALESCE(s.db_privilege,''), COALESCE(s.database_name,''), s.sql_policy_pack_id,
			s.http_policy_pack_id,
			COALESCE(s.k8s_namespaces,'{}'), COALESCE(s.break_glass,false),
			u.username, a.name, aa.username, a.address,
			(s.recording_path <> '' AND s.status IN ('ended','failed','active'))
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		JOIN assets a ON a.id = s.asset_id
		JOIN asset_accounts aa ON aa.id = s.account_id`

func (s *Service) Get(ctx context.Context, id uuid.UUID) (Session, error) {
	row := s.db.Pool.QueryRow(ctx, sessionSelect+` WHERE s.id=$1`, id)
	return scanSession(row)
}

func (s *Service) List(ctx context.Context, f ListFilter) ([]Session, int, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where := ` WHERE 1=1`
	args := []any{}
	i := 1
	if f.OnlyUser != nil {
		where += ` AND s.user_id=$` + itoa(i)
		args = append(args, *f.OnlyUser)
		i++
	}
	if st := strings.TrimSpace(f.Status); st != "" {
		where += ` AND s.status=$` + itoa(i)
		args = append(args, st)
		i++
	}
	if proto := strings.TrimSpace(f.Protocol); proto != "" {
		where += ` AND s.protocol=$` + itoa(i)
		args = append(args, proto)
		i++
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		where += ` AND (u.username ILIKE $` + itoa(i) + ` OR a.name ILIKE $` + itoa(i) + ` OR a.address ILIKE $` + itoa(i) + `)`
		args = append(args, "%"+q+"%")
		i++
	}
	var total int
	countQ := `SELECT COUNT(*) FROM sessions s
		JOIN users u ON u.id = s.user_id
		JOIN assets a ON a.id = s.asset_id
		JOIN asset_accounts aa ON aa.id = s.account_id` + where
	if err := s.db.Pool.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := sessionSelect + where + `
		ORDER BY s.created_at DESC LIMIT $` + itoa(i) + ` OFFSET $` + itoa(i+1)
	args = append(args, f.Limit, f.Offset)
	rows, err := s.db.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, 0, err
		}
		if sess.RecordingPath != "" {
			if s.store != nil {
				sess.HasRecording = s.store.Exists(ctx, sess.RecordingPath)
			} else if _, err := os.Stat(sess.RecordingPath); err == nil {
				sess.HasRecording = true
			} else {
				sess.HasRecording = false
			}
		}
		out = append(out, sess)
	}
	return out, total, rows.Err()
}

func (s *Service) RecordingFile(ctx context.Context, id uuid.UUID) (string, error) {
	sess, err := s.Get(ctx, id)
	if err != nil {
		return "", err
	}
	if sess.RecordingPath == "" {
		return "", fmt.Errorf("no recording")
	}
	path := sess.RecordingPath
	guac := sess.Protocol == "rdp" || sess.Protocol == "vnc" ||
		strings.Contains(filepath.ToSlash(path), "/guac/")
	if s.store != nil {
		_ = s.store.EnsureLocal(ctx, path)
	}
	if guac {
		if best := largestGuacRecording(path); best != "" {
			return best, nil
		}
		return "", fmt.Errorf("recording not found")
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("recording not found")
	}
	return path, nil
}

// largestGuacRecording picks the base file or .N suffix written by guacd
// (name, name.1, name.2, …), preferring the largest complete recording.
func largestGuacRecording(base string) string {
	best := ""
	var bestSize int64
	candidates := []string{base}
	for i := 1; i <= 32; i++ {
		candidates = append(candidates, base+"."+itoa(i))
	}
	for _, p := range candidates {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		if st.Size() > bestSize {
			bestSize = st.Size()
			best = p
		}
	}
	return best
}

type scannable interface {
	Scan(dest ...any) error
}

func scanSession(row scannable) (Session, error) {
	var s Session
	err := row.Scan(
		&s.ID, &s.UserID, &s.AssetID, &s.AccountID, &s.Protocol, &s.Status, &s.ClientIP,
		&s.RecordingPath, &s.ErrorMessage, &s.StartedAt, &s.EndedAt, &s.LastSeenAt, &s.CreatedAt,
		&s.TicketID, &s.Reason, &s.DBPrivilege, &s.DatabaseName, &s.SQLPolicyPackID, &s.HTTPPolicyPackID,
		&s.K8sNamespaces, &s.BreakGlass,
		&s.Username, &s.AssetName, &s.AccountUsername, &s.AssetAddress, &s.HasRecording,
	)
	if err != nil {
		return s, err
	}
	s.Isolated = s.Protocol == "https" && strings.Contains(filepath.ToSlash(s.RecordingPath), "/guac/")
	return s, nil
}

func IsNotFound(err error) bool { return err == pgx.ErrNoRows }

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	return string(b[i:])
}
