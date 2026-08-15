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
	"github.com/keeppam/auth/internal/obs"
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
	Enabled         bool       `json:"enabled"`
	WebhookURL      string     `json:"webhook_url"`
	AuthHeader      string     `json:"auth_header,omitempty"`
	HasAuthHeader   bool       `json:"has_auth_header"`
	TimeoutSec      int        `json:"timeout_sec"`
	LastError       string     `json:"last_error,omitempty"`
	LastSentAt      *time.Time `json:"last_sent_at,omitempty"`
	SMTPEnabled     bool       `json:"smtp_enabled"`
	SMTPHost        string     `json:"smtp_host"`
	SMTPPort        int        `json:"smtp_port"`
	SMTPTLS         string     `json:"smtp_tls"`
	SMTPTLSInsecure bool       `json:"smtp_tls_insecure"`
	SMTPUsername    string     `json:"smtp_username"`
	SMTPPassword    string     `json:"smtp_password,omitempty"`
	HasSMTPPassword bool       `json:"has_smtp_password"`
	SMTPFrom        string     `json:"smtp_from"`
	SMTPLastError   string     `json:"smtp_last_error,omitempty"`
	SMTPLastSentAt  *time.Time `json:"smtp_last_sent_at,omitempty"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
}

type storedSettings struct {
	Settings
	authEnc []byte
	smtpEnc []byte
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
	perm := policy.StagePermission(req.Stage)
	ids, err := s.UsersWithPermission(ctx, perm)
	if err != nil {
		return
	}
	title := "Новый JIT-запрос"
	if len(req.ApprovalStages) > 1 {
		title = "Новый JIT-запрос (этап " + req.Stage + ")"
	}
	body := fmt.Sprintf("%s запросил доступ к %s на %d мин",
		nonEmpty(req.RequesterUsername, req.RequesterID.String()),
		nonEmpty(req.AssetName, req.AssetID.String()), req.DurationMinutes)
	to := FilterRecipients(ids, req.RequesterID)
	s.insert(ctx, to, "jit.created", title, body, "access_request", req.ID.String())
	s.fireWebhook(ctx, JITPayload("jit.created", req))
	s.fireMail(ctx, to, title, body)
}

func (s *Service) OnJITStage(ctx context.Context, req policy.AccessRequest) {
	if req.Status != "pending" {
		return
	}
	perm := policy.StagePermission(req.Stage)
	ids, err := s.UsersWithPermission(ctx, perm)
	if err != nil {
		return
	}
	exclude := []uuid.UUID{req.RequesterID}
	for _, a := range req.Approvals {
		exclude = append(exclude, a.ActorID)
	}
	to := ids
	for _, x := range exclude {
		to = FilterRecipients(to, x)
	}
	title := "JIT: этап " + req.Stage
	body := fmt.Sprintf("%s → %s, нужен %s",
		nonEmpty(req.RequesterUsername, req.RequesterID.String()),
		nonEmpty(req.AssetName, req.AssetID.String()), req.Stage)
	s.insert(ctx, to, "jit.stage", title, body, "access_request", req.ID.String())
	s.fireWebhook(ctx, JITPayload("jit.stage", req))
	s.fireMail(ctx, to, title, body)
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
	s.fireMail(ctx, []uuid.UUID{req.RequesterID}, title, body)
}

func (s *Service) OnAlertmanager(ctx context.Context, evs []obs.AlertEvent) {
	if s == nil || len(evs) == 0 {
		return
	}
	ids, err := s.UsersWithPermission(ctx, "audit.read")
	if err != nil || len(ids) == 0 {
		return
	}
	for _, ev := range evs {
		kind := "obs.alert.firing"
		title := ev.Name
		if ev.Status == "resolved" {
			kind = "obs.alert.resolved"
			title = ev.Name + " resolved"
		}
		body := ev.Summary
		if ev.Description != "" && ev.Description != ev.Summary {
			body = ev.Summary + " — " + ev.Description
		}
		ref := ev.Fingerprint
		if ref == "" {
			ref = ev.Name
		}
		s.insert(ctx, ids, kind, title, body, "alert", ref)
	}
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
	to := FilterRecipients(ids, req.RequesterID)
	s.insert(ctx, to, "checkout.created", title, body, "secret_checkout_request", req.ID.String())
	s.fireMail(ctx, to, title, body)
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
	s.fireMail(ctx, []uuid.UUID{req.RequesterID}, title, body)
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
		"stage":              req.Stage,
		"approval_stages":    req.ApprovalStages,
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

func (s *Service) load(ctx context.Context) (storedSettings, error) {
	var out storedSettings
	var updatedAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT enabled, webhook_url, auth_header_enc, timeout_sec, last_error, last_sent_at,
			smtp_enabled, smtp_host, smtp_port, smtp_tls, smtp_tls_insecure, smtp_username,
			smtp_password_enc, smtp_from, smtp_last_error, smtp_last_sent_at, updated_at
		FROM notify_settings WHERE id=1`).Scan(
		&out.Enabled, &out.WebhookURL, &out.authEnc, &out.TimeoutSec, &out.LastError, &out.LastSentAt,
		&out.SMTPEnabled, &out.SMTPHost, &out.SMTPPort, &out.SMTPTLS, &out.SMTPTLSInsecure, &out.SMTPUsername,
		&out.smtpEnc, &out.SMTPFrom, &out.SMTPLastError, &out.SMTPLastSentAt, &updatedAt)
	if err != nil {
		return storedSettings{}, err
	}
	out.HasAuthHeader = len(out.authEnc) > 0
	out.HasSMTPPassword = len(out.smtpEnc) > 0
	out.UpdatedAt = &updatedAt
	return out, nil
}

func (s *Service) GetSettings(ctx context.Context) (Settings, error) {
	raw, err := s.load(ctx)
	if err != nil {
		return Settings{}, err
	}
	return raw.Settings, nil
}

func (s *Service) UpdateSettings(ctx context.Context, actorID uuid.UUID, in Settings, ip, ua string) (Settings, error) {
	cur, err := s.load(ctx)
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
	authEnc := cur.authEnc
	if in.AuthHeader != "" {
		enc, err := s.env.Encrypt([]byte(strings.TrimSpace(in.AuthHeader)))
		if err != nil {
			return Settings{}, err
		}
		authEnc = enc
	}
	tlsMode, err := normalizeSMTPTLS(in.SMTPTLS)
	if err != nil {
		return Settings{}, err
	}
	port := in.SMTPPort
	if port <= 0 {
		port = 587
	}
	if port > 65535 {
		return Settings{}, fmt.Errorf("smtp_port must be 1..65535")
	}
	host := strings.TrimSpace(in.SMTPHost)
	from := strings.TrimSpace(in.SMTPFrom)
	user := strings.TrimSpace(in.SMTPUsername)
	if in.SMTPEnabled {
		if host == "" {
			return Settings{}, fmt.Errorf("smtp_host required")
		}
		if from == "" || !strings.Contains(from, "@") {
			return Settings{}, fmt.Errorf("smtp_from must be an email")
		}
	}
	smtpEnc := cur.smtpEnc
	if in.SMTPPassword != "" {
		enc, err := s.env.Encrypt([]byte(in.SMTPPassword))
		if err != nil {
			return Settings{}, err
		}
		smtpEnc = enc
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE notify_settings SET enabled=$1, webhook_url=$2, auth_header_enc=$3, timeout_sec=$4,
			smtp_enabled=$5, smtp_host=$6, smtp_port=$7, smtp_tls=$8, smtp_tls_insecure=$9,
			smtp_username=$10, smtp_password_enc=$11, smtp_from=$12,
			updated_at=NOW(), updated_by=$13 WHERE id=1`,
		in.Enabled, url, authEnc, timeout,
		in.SMTPEnabled, host, port, tlsMode, in.SMTPTLSInsecure,
		user, smtpEnc, from, actorID)
	if err != nil {
		return Settings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "settings.notify.updated", "notify_settings", "1", ip, ua, map[string]any{
		"enabled": in.Enabled, "has_url": url != "",
		"smtp_enabled": in.SMTPEnabled, "smtp_host": host, "smtp_tls": tlsMode,
	})
	return s.GetSettings(ctx)
}

func (s *Service) SendTest(ctx context.Context, userID uuid.UUID) error {
	raw, err := s.load(ctx)
	if err != nil {
		return err
	}
	if !raw.SMTPEnabled {
		return fmt.Errorf("SMTP выключен")
	}
	u, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !UsableEmail(u.Email) {
		return fmt.Errorf("у пользователя нет реального email")
	}
	cfg, err := s.smtpConfig(raw)
	if err != nil {
		return err
	}
	if err := sendMailFn(cfg, []string{u.Email}, "KeepPAM SMTP test", "Проверка доставки уведомлений KeepPAM."); err != nil {
		_, _ = s.db.Pool.Exec(ctx, `UPDATE notify_settings SET smtp_last_error=$1 WHERE id=1`, truncate(err.Error(), 400))
		return err
	}
	_, _ = s.db.Pool.Exec(ctx, `UPDATE notify_settings SET smtp_last_error='', smtp_last_sent_at=NOW() WHERE id=1`)
	return nil
}

func (s *Service) smtpConfig(raw storedSettings) (SMTPConfig, error) {
	pass := ""
	if len(raw.smtpEnc) > 0 && s.env != nil {
		plain, err := s.env.Decrypt(raw.smtpEnc)
		if err != nil {
			return SMTPConfig{}, fmt.Errorf("smtp password decrypt")
		}
		pass = string(plain)
	}
	timeout := time.Duration(raw.TimeoutSec) * time.Second
	if timeout < 5*time.Second {
		timeout = 15 * time.Second
	}
	if timeout > 60*time.Second {
		timeout = 60 * time.Second
	}
	return SMTPConfig{
		Host: raw.SMTPHost, Port: raw.SMTPPort, TLS: raw.SMTPTLS, Insecure: raw.SMTPTLSInsecure,
		Username: raw.SMTPUsername, Password: pass, From: raw.SMTPFrom, Timeout: timeout,
	}, nil
}

func (s *Service) emailsFor(ctx context.Context, users []uuid.UUID) []string {
	if len(users) == 0 {
		return nil
	}
	rows, err := s.db.Pool.Query(ctx, `SELECT email FROM users WHERE id = ANY($1::uuid[]) AND status='active'`, users)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]struct{}{}
	var out []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			continue
		}
		if !UsableEmail(email) {
			continue
		}
		email = strings.TrimSpace(email)
		key := strings.ToLower(email)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, email)
	}
	return out
}

func (s *Service) fireMail(ctx context.Context, users []uuid.UUID, title, body string) {
	raw, err := s.load(ctx)
	if err != nil || !raw.SMTPEnabled {
		return
	}
	emails := s.emailsFor(ctx, users)
	if len(emails) == 0 {
		return
	}
	cfg, err := s.smtpConfig(raw)
	if err != nil {
		return
	}
	go func() {
		var lastErr error
		ok := 0
		for _, em := range emails {
			if err := sendMailFn(cfg, []string{em}, title, body); err != nil {
				lastErr = err
				continue
			}
			ok++
		}
		errText := ""
		if lastErr != nil {
			errText = truncate(lastErr.Error(), 400)
			_ = s.aud.Record(context.Background(), nil, "notify.smtp.failed", "notify_settings", "1", "", "notify", map[string]any{
				"error": truncate(lastErr.Error(), 200), "sent": ok,
			})
		}
		if ok > 0 {
			_, _ = s.db.Pool.Exec(context.Background(), `
				UPDATE notify_settings SET smtp_last_error=$1, smtp_last_sent_at=NOW() WHERE id=1`, errText)
		} else if errText != "" {
			_, _ = s.db.Pool.Exec(context.Background(), `
				UPDATE notify_settings SET smtp_last_error=$1 WHERE id=1`, errText)
		}
	}()
}

func (s *Service) fireWebhook(ctx context.Context, payload map[string]any) {
	raw, err := s.load(ctx)
	if err != nil || !raw.Enabled || strings.TrimSpace(raw.WebhookURL) == "" {
		return
	}
	auth := ""
	if len(raw.authEnc) > 0 && s.env != nil {
		if plain, err := s.env.Decrypt(raw.authEnc); err == nil {
			auth = string(plain)
		}
	}
	cfg := raw.Settings
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
