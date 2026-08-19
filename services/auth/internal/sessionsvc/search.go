package sessionsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type EventSearchFilter struct {
	Q        string
	Type     string // empty = forensic types; "all" = any
	Filename string // payload filename/path (file_transfer)
	Protocol string
	ClientIP string
	Hours    int
	OnlyUser *uuid.UUID
	Limit    int
	Offset   int
}

type EventHit struct {
	ID         uuid.UUID      `json:"id"`
	SessionID  uuid.UUID      `json:"session_id"`
	TS         time.Time      `json:"ts"`
	Type       string         `json:"type"`
	Snippet    string         `json:"snippet"`
	Payload    map[string]any `json:"payload"`
	Username   string         `json:"username,omitempty"`
	AssetName  string         `json:"asset_name,omitempty"`
	AssetID    uuid.UUID      `json:"asset_id"`
	Protocol   string         `json:"protocol"`
	Status     string         `json:"status"`
	BreakGlass bool           `json:"break_glass"`
}

func EventSnippet(eventType string, payload map[string]any) string {
	if payload == nil {
		return eventType
	}
	switch eventType {
	case "sql", "sql_denied":
		if s := payloadString(payload, "statement"); s != "" {
			if eventType == "sql_denied" {
				if r := payloadString(payload, "reason"); r != "" {
					return "DENIED " + s + " (" + r + ")"
				}
				return "DENIED " + s
			}
			return s
		}
	case "k8s":
		verb := payloadString(payload, "verb")
		res := payloadString(payload, "resource")
		ns := payloadString(payload, "namespace")
		name := payloadString(payload, "name")
		st := payloadString(payload, "status")
		line := strings.TrimSpace(strings.Join([]string{verb, res}, " "))
		path := name
		if ns != "" && name != "" {
			path = ns + "/" + name
		} else if ns != "" {
			path = ns
		}
		if path != "" {
			line = strings.TrimSpace(line + " " + path)
		}
		if sub := payloadString(payload, "subresource"); sub != "" {
			line = strings.TrimSpace(line + " /" + sub)
		}
		if st != "" {
			line = strings.TrimSpace(line + " → " + st)
		}
		if line != "" {
			return line
		}
	case "app_approved":
		if m := payloadString(payload, "method"); m != "" {
			path := payloadString(payload, "path")
			line := strings.TrimSpace(m + " " + path)
			if o := payloadString(payload, "object"); o != "" {
				return "APPROVED " + line + " (" + o + ")"
			}
			if line != "" {
				return "APPROVED " + line
			}
		}
	case "command", "command_approved":
		if s := payloadString(payload, "command"); s != "" {
			if eventType == "command_approved" {
				return "APPROVED " + s
			}
			return s
		}
	case "output":
		if s := payloadString(payload, "line"); s != "" {
			return s
		}
	case "keystroke":
		if s := payloadString(payload, "line"); s != "" {
			return s
		}
	case "screen_text":
		if s := payloadString(payload, "line"); s != "" {
			return s
		}
	case "command_approval":
		if s := payloadString(payload, "command"); s != "" {
			return "WAITING " + s
		}
	case "command_denied", "dlp", "risk", "http_denied", "app_denied", "app_approval", "egress_denied":
		if s := payloadString(payload, "command"); s != "" {
			return "DENIED " + s
		}
		if s := payloadString(payload, "statement"); s != "" {
			return "DENIED " + s
		}
		if m := payloadString(payload, "method"); m != "" {
			path := payloadString(payload, "path")
			line := strings.TrimSpace(m + " " + path)
			if r := payloadString(payload, "reason"); r != "" {
				return "DENIED " + line + " (" + r + ")"
			}
			if line != "" {
				return "DENIED " + line
			}
		}
		if h := payloadString(payload, "host"); h != "" {
			line := h
			if p := payloadString(payload, "port"); p != "" {
				line += ":" + p
			}
			if r := payloadString(payload, "reason"); r != "" {
				return "DENIED " + line + " (" + r + ")"
			}
			return "DENIED " + line
		}
		if r := payloadString(payload, "reason"); r != "" {
			return "DENIED " + r
		}
	case "file_transfer":
		name := payloadString(payload, "filename")
		if name == "" {
			name = payloadString(payload, "path")
		}
		if name == "" {
			break
		}
		dir := payloadString(payload, "direction")
		proto := payloadString(payload, "protocol")
		line := strings.TrimSpace(strings.Join([]string{proto, dir, name}, " "))
		if captured, ok := payload["captured"].(bool); ok && !captured {
			line += " (audit)"
		}
		return line
	case "egress":
		h := payloadString(payload, "host")
		if h == "" {
			break
		}
		if p := payloadString(payload, "port"); p != "" {
			return h + ":" + p
		}
		return h
	}
	if s := payloadString(payload, "error"); s != "" {
		return eventType + ": " + s
	}
	b, _ := json.Marshal(payload)
	s := string(b)
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	if s == "{}" || s == "null" {
		return eventType
	}
	return s
}

func payloadString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return strings.TrimSpace(fmt.Sprintf("%v", t))
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", t))
	}
}

func likePattern(q string) string {
	q = strings.TrimSpace(q)
	q = strings.ReplaceAll(q, `\`, `\\`)
	q = strings.ReplaceAll(q, `%`, `\%`)
	q = strings.ReplaceAll(q, `_`, `\_`)
	return "%" + q + "%"
}

func (s *Service) SearchEvents(ctx context.Context, f EventSearchFilter) ([]EventHit, int, error) {
	if f.Limit <= 0 || f.Limit > 100 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	if f.Hours <= 0 {
		f.Hours = 168
	}
	if f.Hours > 2160 {
		f.Hours = 2160
	}
	typ := strings.TrimSpace(f.Type)
	q := strings.TrimSpace(f.Q)
	since := time.Now().UTC().Add(-time.Duration(f.Hours) * time.Hour)

	where := []string{"e.ts >= $1"}
	args := []any{since}
	n := 1
	add := func(v any) string {
		n++
		args = append(args, v)
		return fmt.Sprintf("$%d", n)
	}

	switch typ {
	case "", "forensic":
		where = append(where, "e.event_type IN ('sql','sql_denied','k8s','command','command_denied','command_approval','command_approved','output','keystroke','screen_text','dlp','risk','http_denied','app_denied','app_approval','app_approved','egress','egress_denied','file_transfer')")
	case "all":
	default:
		where = append(where, "e.event_type = "+add(typ))
	}
	if q != "" {
		p := add(likePattern(q))
		where = append(where, "(e.payload::text ILIKE "+p+" ESCAPE '\\' OR e.event_type ILIKE "+p+" ESCAPE '\\')")
	}
	if name := strings.TrimSpace(f.Filename); name != "" {
		if typ == "" || typ == "forensic" {
			where = append(where, "e.event_type = 'file_transfer'")
		}
		p := add(likePattern(name))
		where = append(where, "(COALESCE(e.payload->>'filename','') ILIKE "+p+" ESCAPE '\\' OR COALESCE(e.payload->>'path','') ILIKE "+p+" ESCAPE '\\')")
	}
	if proto := strings.TrimSpace(f.Protocol); proto != "" {
		where = append(where, "s.protocol = "+add(proto))
	}
	if ip := strings.TrimSpace(f.ClientIP); ip != "" {
		where = append(where, "s.client_ip ILIKE "+add("%"+ip+"%")+" ESCAPE '\\'")
	}
	if f.OnlyUser != nil {
		where = append(where, "s.user_id = "+add(*f.OnlyUser))
	}
	clause := strings.Join(where, " AND ")

	var total int
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM session_events e
		JOIN sessions s ON s.id = e.session_id
		WHERE `+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limitP := add(f.Limit)
	offP := add(f.Offset)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT e.id, e.session_id, e.ts, e.event_type, e.payload,
			u.username, a.name, s.asset_id, s.protocol, s.status, COALESCE(s.break_glass,false)
		FROM session_events e
		JOIN sessions s ON s.id = e.session_id
		JOIN users u ON u.id = s.user_id
		JOIN assets a ON a.id = s.asset_id
		WHERE `+clause+`
		ORDER BY e.ts DESC
		LIMIT `+limitP+` OFFSET `+offP, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []EventHit
	for rows.Next() {
		var h EventHit
		var raw []byte
		if err := rows.Scan(&h.ID, &h.SessionID, &h.TS, &h.Type, &raw,
			&h.Username, &h.AssetName, &h.AssetID, &h.Protocol, &h.Status, &h.BreakGlass); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(raw, &h.Payload)
		if h.Payload == nil {
			h.Payload = map[string]any{}
		}
		h.Snippet = EventSnippet(h.Type, h.Payload)
		out = append(out, h)
	}
	if out == nil {
		out = []EventHit{}
	}
	return out, total, rows.Err()
}
