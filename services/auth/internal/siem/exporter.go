package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/store"
)

// Run polls audit_events and exports batches according to siem_settings.
func (s *Service) Run(ctx context.Context) {
	for {
		cfg, authEnc, err := s.Get(ctx)
		if err != nil {
			slog.Warn("siem settings", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
			continue
		}
		interval := time.Duration(cfg.PollIntervalSec) * time.Second
		if interval < time.Second {
			interval = 10 * time.Second
		}

		if cfg.Enabled && cfg.Transport != "off" {
			if n, err := s.exportOnce(ctx, cfg, authEnc); err != nil {
				slog.Warn("siem export", "err", err)
				s.setError(ctx, err.Error())
			} else if n > 0 {
				slog.Info("siem exported", "count", n, "transport", cfg.Transport)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (s *Service) exportOnce(ctx context.Context, cfg Settings, authEnc []byte) (int, error) {
	events, err := s.fetchAfter(ctx, cfg.CursorTS, cfg.CursorID, cfg.BatchSize)
	if err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, nil
	}

	switch cfg.Transport {
	case "syslog_udp":
		if err := s.sendSyslog(ctx, "udp", cfg, events); err != nil {
			return 0, err
		}
	case "syslog_tcp":
		if err := s.sendSyslog(ctx, "tcp", cfg, events); err != nil {
			return 0, err
		}
	case "webhook":
		auth, err := s.DecryptAuth(authEnc)
		if err != nil {
			return 0, err
		}
		if err := s.sendWebhook(ctx, cfg, auth, events); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("transport %q disabled", cfg.Transport)
	}

	last := events[len(events)-1]
	if err := s.setCursor(ctx, last.TS, last.ID); err != nil {
		return 0, err
	}
	return len(events), nil
}

func (s *Service) fetchAfter(ctx context.Context, ts *time.Time, id *uuid.UUID, limit int) ([]store.AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows pgx.Rows
	var err error
	if ts == nil || id == nil {
		rows, err = s.db.Pool.Query(ctx, `
			SELECT id, ts, actor_id, action, resource_type, resource_id, ip, user_agent, payload, prev_hash, hash
			FROM audit_events ORDER BY ts ASC, id ASC LIMIT $1`, limit)
	} else {
		rows, err = s.db.Pool.Query(ctx, `
			SELECT id, ts, actor_id, action, resource_type, resource_id, ip, user_agent, payload, prev_hash, hash
			FROM audit_events
			WHERE (ts, id) > ($1::timestamptz, $2::uuid)
			ORDER BY ts ASC, id ASC LIMIT $3`, ts.UTC(), *id, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.AuditEvent
	for rows.Next() {
		var e store.AuditEvent
		var payload []byte
		if err := rows.Scan(&e.ID, &e.TS, &e.ActorID, &e.Action, &e.ResourceType, &e.ResourceID,
			&e.IP, &e.UserAgent, &payload, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(payload, &e.Payload)
		if e.Payload == nil {
			e.Payload = map[string]any{}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Service) sendSyslog(ctx context.Context, network string, cfg Settings, events []store.AuditEvent) error {
	if strings.TrimSpace(cfg.SyslogAddr) == "" {
		return fmt.Errorf("syslog_addr required")
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, network, cfg.SyslogAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	pri := (cfg.SyslogFacility * 8) + 6 // info
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "keeppam"
	}
	for _, e := range events {
		msg := formatEvent(cfg.Format, e)
		line := fmt.Sprintf("<%d>1 %s %s %s - %s - %s\n",
			pri, e.TS.UTC().Format(time.RFC3339Nano), hostname, cfg.SyslogTag, e.ID.String(), msg)
		if _, err := io.WriteString(conn, line); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) sendWebhook(ctx context.Context, cfg Settings, authHeader string, events []store.AuditEvent) error {
	if strings.TrimSpace(cfg.WebhookURL) == "" {
		return fmt.Errorf("webhook_url required")
	}
	body, err := json.Marshal(map[string]any{
		"source": "keeppam",
		"count":  len(events),
		"events": events,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "KeepPAM-SIEM/1.0")
	if authHeader != "" {
		if strings.Contains(authHeader, ":") {
			parts := strings.SplitN(authHeader, ":", 2)
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		} else {
			req.Header.Set("Authorization", authHeader)
		}
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

func formatEvent(format string, e store.AuditEvent) string {
	if format == "cef" {
		actor := ""
		if e.ActorID != nil {
			actor = e.ActorID.String()
		}
		payload, _ := json.Marshal(e.Payload)
		return fmt.Sprintf(
			"CEF:0|KeepPAM|KeepPAM|1.0|%s|%s|5|src=%s suser=%s cs1Label=resourceType cs1=%s cs2Label=resourceId cs2=%s cs3Label=hash cs3=%s cs4Label=payload cs4=%s",
			escapeCEF(e.Action), escapeCEF(e.Action), escapeCEF(e.IP), escapeCEF(actor),
			escapeCEF(e.ResourceType), escapeCEF(e.ResourceID), escapeCEF(e.Hash), escapeCEF(string(payload)),
		)
	}
	b, _ := json.Marshal(e)
	return string(b)
}

func escapeCEF(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "=", "\\=", "\n", "\\n", "\r", "\\r", "|", "\\|")
	return r.Replace(s)
}
