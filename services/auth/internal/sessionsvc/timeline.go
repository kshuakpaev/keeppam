package sessionsvc

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type TimelineFilter struct {
	UserID   uuid.UUID
	From     time.Time
	To       time.Time
	Q        string
	Filename string
	Source   string // all|audit|session
	Limit    int
	Offset   int
}

type TimelineEvent struct {
	ID        uuid.UUID      `json:"id"`
	TS        time.Time      `json:"ts"`
	Source    string         `json:"source"` // audit|session
	Kind      string         `json:"kind"`
	Snippet   string         `json:"snippet"`
	SessionID *uuid.UUID     `json:"session_id,omitempty"`
	AssetID   *uuid.UUID     `json:"asset_id,omitempty"`
	AssetName string         `json:"asset_name,omitempty"`
	Protocol  string         `json:"protocol,omitempty"`
	IP        string         `json:"ip,omitempty"`
	Labels    []string       `json:"labels,omitempty"`
	RiskScore int            `json:"risk_score,omitempty"`
	TicketID  string         `json:"ticket_id,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
}

type TimelineResult struct {
	UserID   uuid.UUID       `json:"user_id"`
	Username string          `json:"username"`
	From     time.Time       `json:"from"`
	To       time.Time       `json:"to"`
	Events   []TimelineEvent `json:"events"`
	Total    int             `json:"total"`
}

func MergeLabels(parts ...[]string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, p := range parts {
		for _, t := range p {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" {
				continue
			}
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	if out == nil {
		return []string{}
	}
	sort.Strings(out)
	return out
}

func AuditSnippet(action, resourceType, resourceID string, payload map[string]any) string {
	action = strings.TrimSpace(action)
	if payload != nil {
		if r := payloadString(payload, "reason"); r != "" {
			return action + ": " + r
		}
		if s := payloadString(payload, "statement"); s != "" {
			return action + " " + s
		}
		if c := payloadString(payload, "command"); c != "" {
			return action + " " + c
		}
	}
	res := strings.TrimSpace(resourceType + " " + resourceID)
	if res != "" {
		return strings.TrimSpace(action + " " + res)
	}
	return action
}

func (s *Service) LookupUsername(ctx context.Context, userID uuid.UUID) (string, error) {
	var name string
	err := s.db.Pool.QueryRow(ctx, `SELECT username FROM users WHERE id=$1`, userID).Scan(&name)
	return name, err
}

func (s *Service) LookupUser(ctx context.Context, idOrName string) (uuid.UUID, string, error) {
	idOrName = strings.TrimSpace(idOrName)
	if idOrName == "" {
		return uuid.Nil, "", pgx.ErrNoRows
	}
	if id, err := uuid.Parse(idOrName); err == nil {
		name, err := s.LookupUsername(ctx, id)
		return id, name, err
	}
	var id uuid.UUID
	var name string
	err := s.db.Pool.QueryRow(ctx, `SELECT id, username FROM users WHERE username=$1`, idOrName).Scan(&id, &name)
	return id, name, err
}

func (s *Service) Timeline(ctx context.Context, f TimelineFilter) (TimelineResult, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	if f.To.IsZero() {
		f.To = time.Now().UTC()
	}
	if f.From.IsZero() {
		f.From = f.To.Add(-24 * time.Hour)
	}
	if f.To.Before(f.From) {
		f.From, f.To = f.To, f.From
	}
	if f.To.Sub(f.From) > 90*24*time.Hour {
		f.From = f.To.Add(-90 * 24 * time.Hour)
	}
	src := strings.ToLower(strings.TrimSpace(f.Source))
	if src != "audit" && src != "session" {
		src = "all"
	}
	uname, err := s.LookupUsername(ctx, f.UserID)
	if err != nil {
		return TimelineResult{}, err
	}
	q := strings.TrimSpace(f.Q)
	like := likePattern(q)
	fname := strings.TrimSpace(f.Filename)

	union, args := timelineUnionSQL(f.UserID, f.From, f.To, src, q != "" || fname != "")
	var extra []string
	if q != "" {
		args = append(args, like)
		p := len(args)
		extra = append(extra, fmt.Sprintf("(x.kind ILIKE $%d ESCAPE '\\' OR COALESCE(x.payload::text,'') ILIKE $%d ESCAPE '\\' OR COALESCE(x.asset_name,'') ILIKE $%d ESCAPE '\\')", p, p, p))
	}
	if fname != "" {
		args = append(args, likePattern(fname))
		p := len(args)
		extra = append(extra, fmt.Sprintf("x.kind = 'file_transfer' AND (COALESCE(x.payload->>'filename','') ILIKE $%d ESCAPE '\\' OR COALESCE(x.payload->>'path','') ILIKE $%d ESCAPE '\\')", p, p))
	}
	where := ""
	if len(extra) > 0 {
		where = " WHERE " + strings.Join(extra, " AND ")
	}

	var total int
	countSQL := `SELECT COUNT(*) FROM (` + union + `) x` + where
	if err := s.db.Pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return TimelineResult{}, err
	}

	args = append(args, f.Limit, f.Offset)
	lim := len(args) - 1
	off := len(args)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT x.id, x.ts, x.source, x.kind, x.payload, x.session_id, x.asset_id, COALESCE(x.asset_name,''),
			COALESCE(x.protocol,''), COALESCE(x.ip,''), COALESCE(x.labels,'{}'), COALESCE(x.risk_score,0), COALESCE(x.ticket_id,'')
		FROM (`+union+`) x`+where+`
		ORDER BY x.ts DESC, x.id DESC
		LIMIT $`+itoa(lim)+` OFFSET $`+itoa(off), args...)
	if err != nil {
		return TimelineResult{}, err
	}
	defer rows.Close()
	var events []TimelineEvent
	for rows.Next() {
		var ev TimelineEvent
		var raw []byte
		var labels []string
		if err := rows.Scan(&ev.ID, &ev.TS, &ev.Source, &ev.Kind, &raw, &ev.SessionID, &ev.AssetID, &ev.AssetName,
			&ev.Protocol, &ev.IP, &labels, &ev.RiskScore, &ev.TicketID); err != nil {
			return TimelineResult{}, err
		}
		_ = json.Unmarshal(raw, &ev.Payload)
		if ev.Payload == nil {
			ev.Payload = map[string]any{}
		}
		ev.Labels = labels
		if ev.Labels == nil {
			ev.Labels = []string{}
		}
		if ev.Source == "session" {
			ev.Snippet = EventSnippet(ev.Kind, ev.Payload)
		} else {
			rt := payloadString(ev.Payload, "resource_type")
			rid := payloadString(ev.Payload, "resource_id")
			ev.Snippet = AuditSnippet(ev.Kind, rt, rid, ev.Payload)
		}
		events = append(events, ev)
	}
	if events == nil {
		events = []TimelineEvent{}
	}
	return TimelineResult{
		UserID: f.UserID, Username: uname, From: f.From.UTC(), To: f.To.UTC(),
		Events: events, Total: total,
	}, rows.Err()
}

func timelineUnionSQL(userID uuid.UUID, from, to time.Time, src string, includeOutput bool) (string, []any) {
	args := []any{userID, from.UTC(), to.UTC()}
	outFilter := ` AND e.event_type NOT IN ('output','keystroke','screen_text')`
	if includeOutput {
		outFilter = ""
	}
	sessionPart := `
		SELECT e.id, e.ts, 'session'::text AS source, e.event_type AS kind, e.payload,
			e.session_id,
			s.asset_id,
			a.name AS asset_name,
			s.protocol,
			s.client_ip AS ip,
			COALESCE(s.labels,'{}') AS labels,
			COALESCE(s.risk_score,0) AS risk_score,
			COALESCE(s.ticket_id,'') AS ticket_id
		FROM session_events e
		JOIN sessions s ON s.id = e.session_id
		JOIN assets a ON a.id = s.asset_id
		WHERE s.user_id=$1 AND e.ts >= $2 AND e.ts <= $3` + outFilter
	auditPart := `
		SELECT ae.id, ae.ts, 'audit'::text AS source, ae.action AS kind,
			COALESCE(ae.payload,'{}'::jsonb) || jsonb_build_object('resource_type', ae.resource_type, 'resource_id', ae.resource_id) AS payload,
			CASE WHEN ae.resource_type = 'session' AND ae.resource_id ~ '^[0-9a-fA-F-]{36}$'
				THEN ae.resource_id::uuid ELSE NULL END AS session_id,
			CASE WHEN COALESCE(ae.payload->>'asset_id','') ~ '^[0-9a-fA-F-]{36}$'
				THEN (ae.payload->>'asset_id')::uuid ELSE NULL END AS asset_id,
			COALESCE(ast.name, '') AS asset_name,
			COALESCE(ae.payload->>'protocol','') AS protocol,
			ae.ip,
			'{}'::text[] AS labels,
			CASE WHEN (ae.payload->>'risk_score') ~ '^[0-9]+$' THEN (ae.payload->>'risk_score')::int ELSE 0 END AS risk_score,
			COALESCE(ae.payload->>'ticket_id','') AS ticket_id
		FROM audit_events ae
		LEFT JOIN assets ast ON ast.id = (
			CASE WHEN COALESCE(ae.payload->>'asset_id','') ~ '^[0-9a-fA-F-]{36}$'
				THEN (ae.payload->>'asset_id')::uuid ELSE NULL END
		)
		WHERE ae.actor_id=$1 AND ae.ts >= $2 AND ae.ts <= $3`
	switch src {
	case "session":
		return sessionPart, args
	case "audit":
		return auditPart, args
	default:
		return sessionPart + ` UNION ALL ` + auditPart, args
	}
}

func WriteTimelineCSV(w io.Writer, res TimelineResult) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"ts", "source", "kind", "snippet", "asset", "protocol", "ip", "session_id", "labels", "risk_score"}); err != nil {
		return err
	}
	for _, e := range res.Events {
		sid := ""
		if e.SessionID != nil {
			sid = e.SessionID.String()
		}
		if err := cw.Write([]string{
			e.TS.UTC().Format(time.RFC3339Nano),
			e.Source,
			e.Kind,
			e.Snippet,
			e.AssetName,
			e.Protocol,
			e.IP,
			sid,
			strings.Join(e.Labels, ","),
			fmt.Sprintf("%d", e.RiskScore),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
