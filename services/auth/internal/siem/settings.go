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
	Transport            string     `json:"transport"` // off|syslog_udp|syslog_tcp|webhook|kafka|nats
	SyslogAddr           string     `json:"syslog_addr"`
	SyslogTag            string     `json:"syslog_tag"`
	SyslogFacility       int        `json:"syslog_facility"`
	WebhookURL           string     `json:"webhook_url"`
	WebhookAuthHeader    string     `json:"webhook_auth_header,omitempty"` // write-only
	HasWebhookAuthHeader bool       `json:"has_webhook_auth_header"`
	KafkaBrokers         string     `json:"kafka_brokers"`
	KafkaTopic           string     `json:"kafka_topic"`
	KafkaUsername        string     `json:"kafka_username"`
	KafkaPassword        string     `json:"kafka_password,omitempty"` // write-only
	HasKafkaPassword     bool       `json:"has_kafka_password"`
	NATSURL              string     `json:"nats_url"`
	NATSSubject          string     `json:"nats_subject"`
	NATSToken            string     `json:"nats_token,omitempty"` // write-only
	HasNATSToken         bool       `json:"has_nats_token"`
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

func validTransport(t string) bool {
	switch t {
	case "off", "syslog_udp", "syslog_tcp", "webhook", "kafka", "nats":
		return true
	default:
		return false
	}
}

func (s *Service) Get(ctx context.Context) (Settings, []byte, error) {
	var out Settings
	var authEnc, kafkaEnc, natsEnc []byte
	var updatedAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT enabled, transport, syslog_addr, syslog_tag, syslog_facility,
			webhook_url, webhook_auth_header_enc, format, batch_size, poll_interval_sec,
			cursor_ts, cursor_id, last_error, last_export_at, updated_at,
			COALESCE(kafka_brokers,''), COALESCE(kafka_topic,''), COALESCE(kafka_username,''), kafka_password_enc,
			COALESCE(nats_url,''), COALESCE(nats_subject,''), nats_token_enc
		FROM siem_settings WHERE id=1`).Scan(
		&out.Enabled, &out.Transport, &out.SyslogAddr, &out.SyslogTag, &out.SyslogFacility,
		&out.WebhookURL, &authEnc, &out.Format, &out.BatchSize, &out.PollIntervalSec,
		&out.CursorTS, &out.CursorID, &out.LastError, &out.LastExportAt, &updatedAt,
		&out.KafkaBrokers, &out.KafkaTopic, &out.KafkaUsername, &kafkaEnc,
		&out.NATSURL, &out.NATSSubject, &natsEnc,
	)
	if err != nil {
		return Settings{}, nil, err
	}
	out.HasWebhookAuthHeader = len(authEnc) > 0
	out.HasKafkaPassword = len(kafkaEnc) > 0
	out.HasNATSToken = len(natsEnc) > 0
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
	if !validTransport(transport) {
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
	kafkaTopic := strings.TrimSpace(in.KafkaTopic)
	if kafkaTopic == "" {
		kafkaTopic = "keeppam.audit"
	}
	natsSubj := strings.TrimSpace(in.NATSSubject)
	if natsSubj == "" {
		natsSubj = "keeppam.audit"
	}
	kafkaBrokers := strings.TrimSpace(in.KafkaBrokers)
	natsURL := strings.TrimSpace(in.NATSURL)

	enabled := in.Enabled && transport != "off"
	if enabled && transport == "kafka" && len(splitBrokers(kafkaBrokers)) == 0 {
		return Settings{}, fmt.Errorf("kafka_brokers required")
	}
	if enabled && transport == "nats" && natsURL == "" {
		return Settings{}, fmt.Errorf("nats_url required")
	}

	if strings.TrimSpace(in.WebhookAuthHeader) != "" {
		enc, err := s.env.Encrypt([]byte(strings.TrimSpace(in.WebhookAuthHeader)))
		if err != nil {
			return Settings{}, err
		}
		authEnc = enc
	}
	kafkaEnc, natsEnc, err := s.loadBusEnc(ctx)
	if err != nil {
		return Settings{}, err
	}
	if strings.TrimSpace(in.KafkaPassword) != "" {
		enc, err := s.env.Encrypt([]byte(strings.TrimSpace(in.KafkaPassword)))
		if err != nil {
			return Settings{}, err
		}
		kafkaEnc = enc
	}
	if strings.TrimSpace(in.NATSToken) != "" {
		enc, err := s.env.Encrypt([]byte(strings.TrimSpace(in.NATSToken)))
		if err != nil {
			return Settings{}, err
		}
		natsEnc = enc
	}

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE siem_settings SET
			enabled=$2, transport=$3, syslog_addr=$4, syslog_tag=$5, syslog_facility=$6,
			webhook_url=$7, webhook_auth_header_enc=$8, format=$9, batch_size=$10, poll_interval_sec=$11,
			kafka_brokers=$12, kafka_topic=$13, kafka_username=$14, kafka_password_enc=$15,
			nats_url=$16, nats_subject=$17, nats_token_enc=$18,
			updated_at=NOW(), updated_by=$19
		WHERE id=$1`,
		1, enabled, transport, strings.TrimSpace(in.SyslogAddr), tag, facility,
		strings.TrimSpace(in.WebhookURL), authEnc, format, batch, poll,
		kafkaBrokers, kafkaTopic, strings.TrimSpace(in.KafkaUsername), kafkaEnc,
		natsURL, natsSubj, natsEnc, actorID)
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

func (s *Service) loadBusEnc(ctx context.Context) (kafkaEnc, natsEnc []byte, err error) {
	err = s.db.Pool.QueryRow(ctx, `
		SELECT kafka_password_enc, nats_token_enc FROM siem_settings WHERE id=1`).Scan(&kafkaEnc, &natsEnc)
	return kafkaEnc, natsEnc, err
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

func (s *Service) busSecret(ctx context.Context, kind string) (string, error) {
	kafkaEnc, natsEnc, err := s.loadBusEnc(ctx)
	if err != nil {
		return "", err
	}
	var enc []byte
	if kind == "kafka" {
		enc = kafkaEnc
	} else {
		enc = natsEnc
	}
	return s.DecryptAuth(enc)
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
