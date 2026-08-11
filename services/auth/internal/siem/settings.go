package siem

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/store"
)

type Settings struct {
	Enabled              bool       `json:"enabled"`
	Transport            string     `json:"transport"` // off|syslog_udp|syslog_tcp|webhook
	SyslogAddr           string     `json:"syslog_addr"`
	SyslogTag            string     `json:"syslog_tag"`
	SyslogFacility       int        `json:"syslog_facility"`
	WebhookURL           string     `json:"webhook_url"`
	WebhookAuthHeader    string     `json:"webhook_auth_header,omitempty"` // write-only
	HasWebhookAuthHeader bool       `json:"has_webhook_auth_header"`
	Format               string     `json:"format"` // json|cef
	BatchSize            int        `json:"batch_size"`
	PollIntervalSec      int        `json:"poll_interval_sec"`
	CursorTS             *time.Time `json:"cursor_ts,omitempty"`
	CursorID             *uuid.UUID `json:"cursor_id,omitempty"`
	LastError            string     `json:"last_error,omitempty"`
	LastExportAt         *time.Time `json:"last_export_at,omitempty"`
	UpdatedAt            *time.Time `json:"updated_at,omitempty"`
}

type Service struct {
	db  *store.DB
	aud *audit.Service
	env *crypto.Envelope
}

func New(db *store.DB, aud *audit.Service, env *crypto.Envelope) *Service {
	return &Service{db: db, aud: aud, env: env}
}

func (s *Service) Get(ctx context.Context) (Settings, []byte, error) {
	var out Settings
	var authEnc []byte
	var updatedAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT enabled, transport, syslog_addr, syslog_tag, syslog_facility,
			webhook_url, webhook_auth_header_enc, format, batch_size, poll_interval_sec,
			cursor_ts, cursor_id, last_error, last_export_at, updated_at
		FROM siem_settings WHERE id=1`).Scan(
		&out.Enabled, &out.Transport, &out.SyslogAddr, &out.SyslogTag, &out.SyslogFacility,
		&out.WebhookURL, &authEnc, &out.Format, &out.BatchSize, &out.PollIntervalSec,
		&out.CursorTS, &out.CursorID, &out.LastError, &out.LastExportAt, &updatedAt,
	)
	if err != nil {
		return Settings{}, nil, err
	}
	out.HasWebhookAuthHeader = len(authEnc) > 0
	out.UpdatedAt = &updatedAt
	return out, authEnc, nil
}

func (s *Service) Update(ctx context.Context, actorID uuid.UUID, in Settings, ip, ua string) (Settings, error) {
	cur, authEnc, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}

	transport := strings.TrimSpace(in.Transport)
	if transport == "" {
		transport = "off"
	}
	switch transport {
	case "off", "syslog_udp", "syslog_tcp", "webhook":
	default:
		return Settings{}, fmt.Errorf("invalid transport")
	}
	format := strings.TrimSpace(in.Format)
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "cef" {
		return Settings{}, fmt.Errorf("invalid format")
	}
	batch := in.BatchSize
	if batch <= 0 {
		batch = 100
	}
	if batch > 1000 {
		batch = 1000
	}
	poll := in.PollIntervalSec
	if poll <= 0 {
		poll = 10
	}
	if poll > 3600 {
		poll = 3600
	}
	tag := strings.TrimSpace(in.SyslogTag)
	if tag == "" {
		tag = "keeppam"
	}
	facility := in.SyslogFacility
	if facility < 0 || facility > 23 {
		facility = 16
	}

	if strings.TrimSpace(in.WebhookAuthHeader) != "" {
		enc, err := s.env.Encrypt([]byte(strings.TrimSpace(in.WebhookAuthHeader)))
		if err != nil {
			return Settings{}, err
		}
		authEnc = enc
	}

	enabled := in.Enabled && transport != "off"
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE siem_settings SET
			enabled=$2, transport=$3, syslog_addr=$4, syslog_tag=$5, syslog_facility=$6,
			webhook_url=$7, webhook_auth_header_enc=$8, format=$9, batch_size=$10, poll_interval_sec=$11,
			updated_at=NOW(), updated_by=$12
		WHERE id=$1`,
		1, enabled, transport, strings.TrimSpace(in.SyslogAddr), tag, facility,
		strings.TrimSpace(in.WebhookURL), authEnc, format, batch, poll, actorID)
	if err != nil {
		return Settings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "settings.siem.updated", "siem_settings", "1", ip, ua, map[string]any{
		"enabled": enabled, "transport": transport, "format": format,
		"prev_enabled": cur.Enabled, "prev_transport": cur.Transport,
	})
	out, _, err := s.Get(ctx)
	return out, err
}

func (s *Service) DecryptAuth(enc []byte) (string, error) {
	if len(enc) == 0 {
		return "", nil
	}
	b, err := s.env.Decrypt(enc)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *Service) setCursor(ctx context.Context, ts time.Time, id uuid.UUID) error {
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE siem_settings SET cursor_ts=$2, cursor_id=$3, last_export_at=NOW(), last_error='' WHERE id=1`,
		1, ts.UTC(), id)
	return err
}

func (s *Service) setError(ctx context.Context, msg string) {
	if len(msg) > 500 {
		msg = msg[:500] + "…"
	}
	_, _ = s.db.Pool.Exec(ctx, `UPDATE siem_settings SET last_error=$2 WHERE id=1`, 1, msg)
}
