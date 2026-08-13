package notify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/store"
)

type Notification struct {
	ID        uuid.UUID  `json:"id"`
	Kind      string     `json:"kind"`
	Title     string     `json:"title"`
	Body      string     `json:"body"`
	RefType   string     `json:"ref_type"`
	RefID     string     `json:"ref_id"`
	ReadAt    *time.Time `json:"read_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type Settings struct {
	Enabled       bool       `json:"enabled"`
	WebhookURL    string     `json:"webhook_url"`
	AuthHeader    string     `json:"auth_header,omitempty"`
	HasAuthHeader bool       `json:"has_auth_header"`
	TimeoutSec    int        `json:"timeout_sec"`
	LastError     string     `json:"last_error,omitempty"`
	LastSentAt    *time.Time `json:"last_sent_at,omitempty"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
}

type Service struct {
	db  *store.DB
	aud *audit.Service
	env *crypto.Envelope
}

func New(db *store.DB, aud *audit.Service, env *crypto.Envelope) *Service {
	return &Service{db: db, aud: aud, env: env}
}

func FilterRecipients(ids []uuid.UUID, exclude uuid.UUID) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ids))
	seen := map[uuid.UUID]struct{}{}
	for _, id := range ids {
		if id == uuid.Nil || id == exclude {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func (s *Service) UsersWithPermission(ctx context.Context, perm string) ([]uuid.UUID, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT DISTINCT u.id
		FROM users u
		JOIN user_role_bindings urb ON urb.user_id = u.id
		JOIN role_permissions rp ON rp.role_id = urb.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE p.name = $1 AND u.status = 'active'`, perm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Service) List(ctx context.Context, userID uuid.UUID, limit int) ([]Notification, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, kind, title, body, ref_type, ref_id, read_at, created_at
		FROM notifications
		WHERE user_id=$1
		ORDER BY (read_at IS NULL) DESC, created_at DESC
		LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		if err := rows.Scan(&n.ID, &n.Kind, &n.Title, &n.Body, &n.RefType, &n.RefID, &n.ReadAt, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	if out == nil {
		out = []Notification{}
	}
	return out, rows.Err()
}

func (s *Service) UnreadCount(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM notifications WHERE user_id=$1 AND read_at IS NULL`, userID).Scan(&n)
	return n, err
}

func (s *Service) MarkRead(ctx context.Context, userID, id uuid.UUID) error {
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE notifications SET read_at=NOW() WHERE id=$1 AND user_id=$2 AND read_at IS NULL`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

func (s *Service) MarkAllRead(ctx context.Context, userID uuid.UUID) error {
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE notifications SET read_at=NOW() WHERE user_id=$1 AND read_at IS NULL`, userID)
	return err
}

func (s *Service) OnJITCreated(ctx context.Context, req policy.AccessRequest) {
	ids, err := s.UsersWithPermission(ctx, "access.approve")
	if err != nil {
		return
	}
	title := "Новый JIT-запрос"
	body := fmt.Sprintf("%s запросил доступ к %s на %d мин",
		nonEmpty(req.RequesterUsername, req.RequesterID.String()),
		nonEmpty(req.AssetName, req.AssetID.String()), req.DurationMinutes)
	s.insert(ctx, FilterRecipients(ids, req.RequesterID), "jit.created", title, body, "access_request", req.ID.String())
	s.fireWebhook(ctx, JITPayload("jit.created", req))
}

func (s *Service) OnJITDecided(ctx context.Context, req policy.AccessRequest) {
	kind := "jit.approved"
	title := "JIT-запрос одобрен"
	if req.Status == "denied" {
		kind = "jit.denied"
		title = "JIT-запрос отклонён"
	}
	body := fmt.Sprintf("%s: %s", nonEmpty(req.AssetName, req.AssetID.String()), req.Status)
	s.insert(ctx, []uuid.UUID{req.RequesterID}, kind, title, body, "access_request", req.ID.String())
	s.fireWebhook(ctx, JITPayload(kind, req))
}

func (s *Service) OnCheckoutCreated(ctx context.Context, req assets.CheckoutRequest) {
	ids, err := s.UsersWithPermission(ctx, "assets.write")
	if err != nil {
		return
	}
	title := "Checkout секрета"
	body := fmt.Sprintf("%s запросил %s@%s",
		nonEmpty(req.RequesterName, req.RequesterID.String()),
		nonEmpty(req.Username, req.AccountID.String()),
		nonEmpty(req.AssetName, req.AssetID.String()))
	s.insert(ctx, FilterRecipients(ids, req.RequesterID), "checkout.created", title, body, "secret_checkout_request", req.ID.String())
}

func (s *Service) OnCheckoutDecided(ctx context.Context, req assets.CheckoutRequest) {
	kind := "checkout.approved"
	title := "Checkout одобрен"
	if req.Status == "denied" {
		kind = "checkout.denied"
		title = "Checkout отклонён"
	}
	body := fmt.Sprintf("%s@%s: %s",
		nonEmpty(req.Username, req.AccountID.String()),
		nonEmpty(req.AssetName, req.AssetID.String()), req.Status)
	s.insert(ctx, []uuid.UUID{req.RequesterID}, kind, title, body, "secret_checkout_request", req.ID.String())
}

func JITPayload(event string, req policy.AccessRequest) map[string]any {
	var approver any
	if req.ApproverID != nil {
		approver = req.ApproverID.String()
	}
	return map[string]any{
		"source":             "keeppam",
		"event":              event,
		"id":                 req.ID.String(),
		"asset_id":           req.AssetID.String(),
		"asset_name":         req.AssetName,
		"requester_id":       req.RequesterID.String(),
		"requester_username": req.RequesterUsername,
		"duration_minutes":   req.DurationMinutes,
		"reason":             req.Reason,
		"ticket_id":          req.TicketID,
		"status":             req.Status,
		"approver_id":        approver,
		"ts":                 time.Now().UTC().Format(time.RFC3339),
	}
}

func (s *Service) insert(ctx context.Context, users []uuid.UUID, kind, title, body, refType, refID string) {
	now := time.Now().UTC()
	for _, uid := range users {
		if uid == uuid.Nil {
			continue
		}
		_, _ = s.db.Pool.Exec(ctx, `
			INSERT INTO notifications (id, user_id, kind, title, body, ref_type, ref_id, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			store.NewID(), uid, kind, title, body, refType, refID, now)
	}
}

func (s *Service) GetSettings(ctx context.Context) (Settings, []byte, error) {
	var out Settings
	var authEnc []byte
	var updatedAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT enabled, webhook_url, auth_header_enc, timeout_sec, last_error, last_sent_at, updated_at
		FROM notify_settings WHERE id=1`).Scan(
		&out.Enabled, &out.WebhookURL, &authEnc, &out.TimeoutSec, &out.LastError, &out.LastSentAt, &updatedAt)
	if err != nil {
		return Settings{}, nil, err
	}
	out.HasAuthHeader = len(authEnc) > 0
	out.UpdatedAt = &updatedAt
	return out, authEnc, nil
}

func (s *Service) UpdateSettings(ctx context.Context, actorID uuid.UUID, in Settings, ip, ua string) (Settings, error) {
	cur, authEnc, err := s.GetSettings(ctx)
	if err != nil {
		return Settings{}, err
	}
	timeout := in.TimeoutSec
	if timeout <= 0 {
		timeout = 5
	}
	if timeout > 30 {
		timeout = 30
	}
	url := strings.TrimSpace(in.WebhookURL)
	if in.AuthHeader != "" {
		enc, err := s.env.Encrypt([]byte(strings.TrimSpace(in.AuthHeader)))
		if err != nil {
			return Settings{}, err
		}
		authEnc = enc
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE notify_settings SET enabled=$1, webhook_url=$2, auth_header_enc=$3, timeout_sec=$4,
			updated_at=NOW(), updated_by=$5 WHERE id=1`,
		in.Enabled, url, authEnc, timeout, actorID)
	if err != nil {
		return Settings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "settings.notify.updated", "notify_settings", "1", ip, ua, map[string]any{
		"enabled": in.Enabled, "has_url": url != "",
	})
	out, _, err := s.GetSettings(ctx)
	if err != nil {
		return cur, err
	}
	return out, nil
}

func (s *Service) fireWebhook(ctx context.Context, payload map[string]any) {
	cfg, authEnc, err := s.GetSettings(ctx)
	if err != nil || !cfg.Enabled || strings.TrimSpace(cfg.WebhookURL) == "" {
		return
	}
	auth := ""
	if len(authEnc) > 0 && s.env != nil {
		if plain, err := s.env.Decrypt(authEnc); err == nil {
			auth = string(plain)
		}
	}
	go func() {
		wctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.TimeoutSec)*time.Second)
		defer cancel()
		if err := PostJSON(wctx, cfg.WebhookURL, auth, time.Duration(cfg.TimeoutSec)*time.Second, payload); err != nil {
			_, _ = s.db.Pool.Exec(context.Background(), `
				UPDATE notify_settings SET last_error=$1 WHERE id=1`, truncate(err.Error(), 400))
			_ = s.aud.Record(context.Background(), nil, "notify.webhook.failed", "notify_settings", "1", "", "notify", map[string]any{
				"event": payload["event"], "error": truncate(err.Error(), 200),
			})
			return
		}
		_, _ = s.db.Pool.Exec(context.Background(), `
			UPDATE notify_settings SET last_error='', last_sent_at=NOW() WHERE id=1`)
	}()
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
