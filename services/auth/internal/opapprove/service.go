package opapprove

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/store"
)

const DefaultWait = 60 * time.Second

type Approval struct {
	ID           uuid.UUID  `json:"id"`
	SessionID    uuid.UUID  `json:"session_id"`
	UserID       uuid.UUID  `json:"user_id"`
	AssetID      uuid.UUID  `json:"asset_id"`
	Method       string     `json:"method"`
	Path         string     `json:"path"`
	Object       string     `json:"object"`
	PackName     string     `json:"pack_name"`
	Channel      string     `json:"channel"`
	Status       string     `json:"status"`
	ApproverID   *uuid.UUID `json:"approver_id,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	ExpiresAt    time.Time  `json:"expires_at"`
	Username     string     `json:"username,omitempty"`
	AssetName    string     `json:"asset_name,omitempty"`
	ApproverName string     `json:"approver_username,omitempty"`
}

type HoldInput struct {
	SessionID  uuid.UUID
	UserID     uuid.UUID
	AssetID    uuid.UUID
	Username   string
	AssetName  string
	Method     string
	Path       string
	Object     string
	PackName   string
	Channel    string
	IP         string
	BreakGlass bool
	Snapshot   *policy.Snapshot
}

type HoldResult struct {
	Allow  bool
	Code   string
	Reason string
	Rec    Approval
}

type Service struct {
	db        *store.DB
	rdb       *redis.Client
	aud       *audit.Service
	OnCreated func(context.Context, Approval)
}

func New(db *store.DB, rdb *redis.Client, aud *audit.Service) *Service {
	return &Service{db: db, rdb: rdb, aud: aud}
}

func SkipWait(breakGlass bool, snap *policy.Snapshot) bool {
	if breakGlass {
		return true
	}
	return snap != nil && (snap.AdminBypass || snap.BreakGlass)
}

func NormalizeChannel(ch string) string {
	switch strings.ToLower(strings.TrimSpace(ch)) {
	case "k8s", "ssh":
		return strings.ToLower(strings.TrimSpace(ch))
	default:
		return "http"
	}
}

func auditAction(channel, suffix string) string {
	if NormalizeChannel(channel) == "ssh" {
		return "session.command." + suffix
	}
	return "session.app." + suffix
}

func redisChan(id uuid.UUID) string {
	return "keeppam:op-approval:" + id.String()
}

func (s *Service) Hold(ctx context.Context, in HoldInput) HoldResult {
	if s == nil || s.db == nil {
		return HoldResult{Allow: false, Code: "approval_required", Reason: "approval service unavailable"}
	}
	if SkipWait(in.BreakGlass, in.Snapshot) {
		return HoldResult{Allow: true}
	}
	rec, err := s.Wait(ctx, in)
	if err != nil {
		return HoldResult{Allow: false, Code: "approval_timeout", Reason: err.Error(), Rec: rec}
	}
	switch rec.Status {
	case "approved":
		_ = s.aud.Record(ctx, &in.UserID, auditAction(in.Channel, "approved"), "session", in.SessionID.String(), in.IP, in.Channel, map[string]any{
			"method": in.Method, "path": in.Path, "object": in.Object, "approval_id": rec.ID.String(),
		})
		return HoldResult{Allow: true, Rec: rec}
	case "denied":
		reason := "approval denied: " + in.Object
		if NormalizeChannel(in.Channel) != "ssh" {
			reason = "app object approval denied: " + in.Object
		}
		_ = s.aud.Record(ctx, &in.UserID, auditAction(in.Channel, "denied"), "session", in.SessionID.String(), in.IP, in.Channel, map[string]any{
			"method": in.Method, "path": in.Path, "object": in.Object, "code": "approval_denied", "approval_id": rec.ID.String(),
		})
		return HoldResult{Allow: false, Code: "approval_denied", Reason: reason, Rec: rec}
	default:
		reason := "approval timed out: " + in.Object
		if NormalizeChannel(in.Channel) != "ssh" {
			reason = "app object approval timed out: " + in.Object
		}
		_ = s.aud.Record(ctx, &in.UserID, auditAction(in.Channel, "approval_timeout"), "session", in.SessionID.String(), in.IP, in.Channel, map[string]any{
			"method": in.Method, "path": in.Path, "object": in.Object, "approval_id": rec.ID.String(),
		})
		return HoldResult{Allow: false, Code: "approval_timeout", Reason: reason, Rec: rec}
	}
}

func (s *Service) Wait(ctx context.Context, in HoldInput) (Approval, error) {
	rec, created, err := s.createOrReuse(ctx, in)
	if err != nil {
		return Approval{}, err
	}
	if created {
		_ = s.aud.Record(ctx, &in.UserID, auditAction(in.Channel, "approval_required"), "session", in.SessionID.String(), in.IP, in.Channel, map[string]any{
			"method": in.Method, "path": in.Path, "object": in.Object, "pack": in.PackName, "approval_id": rec.ID.String(),
		})
		if s.OnCreated != nil {
			s.OnCreated(ctx, rec)
		}
	}
	if rec.Status != "pending" {
		return rec, nil
	}
	waitCtx, cancel := context.WithDeadline(ctx, rec.ExpiresAt)
	defer cancel()
	if s.rdb != nil {
		sub := s.rdb.Subscribe(waitCtx, redisChan(rec.ID))
		defer func() { _ = sub.Close() }()
		ch := sub.Channel()
		ticker := time.NewTicker(400 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-waitCtx.Done():
				return s.expireIfPending(context.Background(), rec.ID)
			case <-ticker.C:
				cur, err := s.get(waitCtx, rec.ID)
				if err == nil && cur.Status != "pending" {
					return cur, nil
				}
			case msg, ok := <-ch:
				if !ok {
					return s.expireIfPending(context.Background(), rec.ID)
				}
				if msg != nil && msg.Payload != "" && msg.Payload != "pending" {
					cur, err := s.get(waitCtx, rec.ID)
					if err == nil {
						return cur, nil
					}
				}
			}
		}
	}
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-waitCtx.Done():
			return s.expireIfPending(context.Background(), rec.ID)
		case <-ticker.C:
			cur, err := s.get(waitCtx, rec.ID)
			if err == nil && cur.Status != "pending" {
				return cur, nil
			}
		}
	}
}

func clipPath(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 1024 {
		return s[:1024]
	}
	return s
}

func (s *Service) createOrReuse(ctx context.Context, in HoldInput) (Approval, bool, error) {
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	path := clipPath(in.Path)
	object := strings.TrimSpace(in.Object)
	ch := NormalizeChannel(in.Channel)
	var existing Approval
	err := s.db.Pool.QueryRow(ctx, approvalSelect+`
		WHERE o.session_id=$1 AND o.method=$2 AND o.path=$3 AND o.status='pending' AND o.expires_at > NOW()
		ORDER BY o.created_at DESC LIMIT 1`, in.SessionID, method, path).Scan(scanDest(&existing)...)
	if err == nil {
		return existing, false, nil
	}
	if err != nil && err != pgx.ErrNoRows {
		return Approval{}, false, err
	}
	id := store.NewID()
	expires := time.Now().UTC().Add(DefaultWait)
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO session_op_approvals
			(id, session_id, user_id, asset_id, method, path, object_name, pack_name, channel, status, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',NOW(),$10)`,
		id, in.SessionID, in.UserID, in.AssetID, method, path, object, in.PackName, ch, expires)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			err = s.db.Pool.QueryRow(ctx, approvalSelect+`
				WHERE o.session_id=$1 AND o.method=$2 AND o.path=$3 AND o.status='pending' AND o.expires_at > NOW()
				ORDER BY o.created_at DESC LIMIT 1`, in.SessionID, method, path).Scan(scanDest(&existing)...)
			if err == nil {
				return existing, false, nil
			}
		}
		return Approval{}, false, err
	}
	rec, err := s.get(ctx, id)
	return rec, true, err
}

func (s *Service) Decide(ctx context.Context, actorID, id uuid.UUID, approve bool, ip, ua string) (Approval, error) {
	cur, err := s.get(ctx, id)
	if err != nil {
		return Approval{}, err
	}
	if cur.Status != "pending" {
		return Approval{}, fmt.Errorf("approval already %s", cur.Status)
	}
	if time.Now().After(cur.ExpiresAt) {
		return s.expireIfPending(ctx, id)
	}
	if actorID == cur.UserID {
		return Approval{}, fmt.Errorf("cannot approve own request")
	}
	status := "denied"
	if approve {
		status = "approved"
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE session_op_approvals
		SET status=$2, approver_id=$3, decided_at=NOW()
		WHERE id=$1 AND status='pending'`, id, status, actorID)
	if err != nil {
		return Approval{}, err
	}
	if tag.RowsAffected() == 0 {
		return Approval{}, fmt.Errorf("approval already decided")
	}
	if s.rdb != nil {
		_ = s.rdb.Publish(ctx, redisChan(id), status).Err()
	}
	action := "session.op.denied"
	if approve {
		action = "session.op.approved"
	}
	_ = s.aud.Record(ctx, &actorID, action, "session_op_approval", id.String(), ip, ua, map[string]any{
		"session_id": cur.SessionID.String(), "object": cur.Object, "method": cur.Method, "path": cur.Path,
	})
	return s.get(ctx, id)
}

func (s *Service) ListPending(ctx context.Context) ([]Approval, error) {
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE session_op_approvals SET status='expired', decided_at=NOW()
		WHERE status='pending' AND expires_at < NOW()`)
	rows, err := s.db.Pool.Query(ctx, approvalSelect+`
		WHERE o.status='pending'
		ORDER BY o.created_at DESC
		LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		var a Approval
		if err := rows.Scan(scanDest(&a)...); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if out == nil {
		out = []Approval{}
	}
	return out, rows.Err()
}

func (s *Service) CountPending(ctx context.Context, excludeUser uuid.UUID) (int, error) {
	var n int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM session_op_approvals
		WHERE status='pending' AND expires_at > NOW() AND user_id <> $1`, excludeUser).Scan(&n)
	return n, err
}

func (s *Service) ExpireSession(ctx context.Context, sessionID uuid.UUID) {
	rows, err := s.db.Pool.Query(ctx, `
		UPDATE session_op_approvals SET status='expired', decided_at=NOW()
		WHERE session_id=$1 AND status='pending'
		RETURNING id`, sessionID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		if rows.Scan(&id) == nil && s.rdb != nil {
			_ = s.rdb.Publish(ctx, redisChan(id), "expired").Err()
		}
	}
}

func (s *Service) expireIfPending(ctx context.Context, id uuid.UUID) (Approval, error) {
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE session_op_approvals SET status='expired', decided_at=NOW()
		WHERE id=$1 AND status='pending'`, id)
	if s.rdb != nil {
		_ = s.rdb.Publish(ctx, redisChan(id), "expired").Err()
	}
	return s.get(ctx, id)
}

func (s *Service) get(ctx context.Context, id uuid.UUID) (Approval, error) {
	var a Approval
	err := s.db.Pool.QueryRow(ctx, approvalSelect+` WHERE o.id=$1`, id).Scan(scanDest(&a)...)
	return a, err
}

const approvalSelect = `
		SELECT o.id, o.session_id, o.user_id, o.asset_id, o.method, o.path, o.object_name, o.pack_name,
			o.channel, o.status, o.approver_id, o.created_at, o.decided_at, o.expires_at,
			COALESCE(u.username,''), COALESCE(a.name,''), COALESCE(ap.username,'')
		FROM session_op_approvals o
		LEFT JOIN users u ON u.id = o.user_id
		LEFT JOIN assets a ON a.id = o.asset_id
		LEFT JOIN users ap ON ap.id = o.approver_id`

func scanDest(a *Approval) []any {
	return []any{
		&a.ID, &a.SessionID, &a.UserID, &a.AssetID, &a.Method, &a.Path, &a.Object, &a.PackName,
		&a.Channel, &a.Status, &a.ApproverID, &a.CreatedAt, &a.DecidedAt, &a.ExpiresAt,
		&a.Username, &a.AssetName, &a.ApproverName,
	}
}

func IsNotFound(err error) bool { return err == pgx.ErrNoRows }
