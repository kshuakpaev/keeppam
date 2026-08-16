package compliance

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	CatAccess      = "access"
	CatPrivileged  = "privileged"
	CatApprovals   = "approvals"
	CatConnections = "connections"
	CatCommands    = "commands"
	CatSQL         = "sql"
	CatDownloads   = "downloads"
	CatChanges     = "changes"
	CatRevoked     = "revoked"

	maxReportWindow = 90 * 24 * time.Hour
	defaultDays     = 30
	maxDays         = 90
	defaultLimit    = 200
	maxLimit        = 500
)

type ReportInput struct {
	From      string
	To        string
	Days      int
	Framework string
	Limit     int
}

type FrameworkControl struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Categories []string `json:"categories"`
}

type ReportSummary struct {
	Access      int `json:"access"`
	Privileged  int `json:"privileged"`
	Approvals   int `json:"approvals"`
	Connections int `json:"connections"`
	Commands    int `json:"commands"`
	SQL         int `json:"sql"`
	Downloads   int `json:"downloads"`
	Changes     int `json:"changes"`
	Revoked     int `json:"revoked"`
}

type ReportSnapshot struct {
	ACLLive          int `json:"acl_live"`
	SessionsActive   int `json:"sessions_active"`
	JITPending       int `json:"jit_pending"`
	BreakGlassActive int `json:"break_glass_active"`
	LegalHolds       int `json:"legal_holds"`
}

type EvidenceRow struct {
	ID           uuid.UUID `json:"id"`
	TS           time.Time `json:"ts"`
	Category     string    `json:"category"`
	Source       string    `json:"source"`
	Actor        string    `json:"actor"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Detail       string    `json:"detail"`
	IP           string    `json:"ip,omitempty"`
}

type Report struct {
	GeneratedAt   time.Time          `json:"generated_at"`
	From          time.Time          `json:"from"`
	To            time.Time          `json:"to"`
	Framework     string             `json:"framework"`
	Controls      []FrameworkControl `json:"controls"`
	Summary       ReportSummary      `json:"summary"`
	Snapshot      ReportSnapshot     `json:"snapshot"`
	Evidence      []EvidenceRow      `json:"evidence"`
	EvidenceTotal int                `json:"evidence_total"`
	Truncated     bool               `json:"truncated"`
	Notes         []string           `json:"notes"`
}

func NormalizeFramework(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "iso27001", "iso", "iso-27001", "iso_27001":
		return "iso27001"
	case "pci", "pci-dss", "pcidss", "pci_dss":
		return "pci"
	case "soc2", "soc-2", "soc_2":
		return "soc2"
	case "nist":
		return "nist"
	default:
		return "all"
	}
}

func FrameworkControls(fw string) []FrameworkControl {
	iso := []FrameworkControl{
		{ID: "A.9", Title: "Access control", Categories: []string{CatAccess, CatPrivileged, CatApprovals, CatRevoked}},
		{ID: "A.12.4", Title: "Logging and monitoring", Categories: []string{CatConnections, CatCommands, CatSQL, CatDownloads}},
		{ID: "A.8.1 / A.12.1", Title: "Asset and change control", Categories: []string{CatChanges}},
	}
	pci := []FrameworkControl{
		{ID: "7", Title: "Restrict access to cardholder data", Categories: []string{CatAccess, CatPrivileged, CatRevoked}},
		{ID: "8", Title: "Identify and authenticate access", Categories: []string{CatChanges}},
		{ID: "10", Title: "Track and monitor all access", Categories: []string{CatConnections, CatCommands, CatSQL, CatDownloads, CatApprovals}},
	}
	soc2 := []FrameworkControl{
		{ID: "CC6", Title: "Logical access", Categories: []string{CatAccess, CatPrivileged, CatApprovals, CatRevoked}},
		{ID: "CC7", Title: "System operations", Categories: []string{CatConnections, CatCommands, CatSQL, CatDownloads, CatChanges}},
	}
	nist := []FrameworkControl{
		{ID: "AC", Title: "Access Control", Categories: []string{CatAccess, CatPrivileged, CatApprovals, CatRevoked}},
		{ID: "AU", Title: "Audit and Accountability", Categories: []string{CatConnections, CatCommands, CatSQL, CatDownloads}},
		{ID: "CM", Title: "Configuration Management", Categories: []string{CatChanges}},
	}
	switch NormalizeFramework(fw) {
	case "iso27001":
		return iso
	case "pci":
		return pci
	case "soc2":
		return soc2
	case "nist":
		return nist
	default:
		out := make([]FrameworkControl, 0, len(iso)+len(pci)+len(soc2)+len(nist))
		prefix := func(tag string, list []FrameworkControl) {
			for _, c := range list {
				c.ID = tag + ":" + c.ID
				out = append(out, c)
			}
		}
		prefix("iso27001", iso)
		prefix("pci", pci)
		prefix("soc2", soc2)
		prefix("nist", nist)
		return out
	}
}

func ParseReportWindow(fromStr, toStr string, days int, now time.Time) (time.Time, time.Time, error) {
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	from, fromOK, _ := parseReportTime(fromStr)
	to, toOK, toDate := parseReportTime(toStr)
	if toOK && toDate {
		to = to.Add(24*time.Hour - time.Nanosecond)
	}
	if fromOK && toOK {
		if to.Before(from) {
			from, to = to, from
		}
		if to.Sub(from) > maxReportWindow {
			from = to.Add(-maxReportWindow)
		}
		return from, to, nil
	}
	if days <= 0 {
		days = defaultDays
	}
	if days > maxDays {
		days = maxDays
	}
	if !toOK {
		to = now
	}
	if !fromOK {
		from = to.Add(-time.Duration(days) * 24 * time.Hour)
	}
	if to.Before(from) {
		from, to = to, from
	}
	if to.Sub(from) > maxReportWindow {
		from = to.Add(-maxReportWindow)
	}
	return from, to, nil
}

func parseReportTime(s string) (time.Time, bool, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false, false
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), true, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), true, false
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), true, true
	}
	return time.Time{}, false, false
}

// EvidenceCategory maps an audit action or session event type to a report bucket.
// Empty string = noise (risk eval, login, settings, …).
func EvidenceCategory(source, kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "session" {
		switch kind {
		case "sql", "sql_denied":
			return CatSQL
		case "command_denied", "command", "k8s", "http_denied", "app_denied", "app_approval", "risk":
			return CatCommands
		case "dlp":
			return CatDownloads
		case "created", "started", "ended":
			return CatConnections
		default:
			return ""
		}
	}
	switch kind {
	case "asset.acl.granted":
		return CatAccess
	case "asset.acl.revoked", "access.request.cancelled", "user.disabled":
		return CatRevoked
	case "access.breakglass.opened", "session.admin_bypass":
		return CatPrivileged
	case "access.request.approved", "access.request.denied", "access.request.stage",
		"asset.account.checkout.approved", "asset.account.checkout.denied":
		return CatApprovals
	case "session.created", "session.started", "session.ended", "session.denied",
		"app.access.granted", "app.access.denied", "k8s.access.granted", "k8s.access.denied":
		return CatConnections
	case "session.sql", "session.sql.denied":
		return CatSQL
	case "asset.account.secret_revealed", "session.export_mp4", "session.dlp.denied":
		return CatDownloads
	case "session.command.denied", "session.command.approval_required", "session.risk.denied",
		"session.app.denied", "session.app.approval_required":
		return CatCommands
	}
	switch {
	case strings.HasPrefix(kind, "user.login"):
		return ""
	case strings.HasPrefix(kind, "access.request."):
		return CatApprovals
	case strings.HasPrefix(kind, "user."),
		strings.HasPrefix(kind, "group."),
		strings.HasPrefix(kind, "role."),
		strings.HasPrefix(kind, "jea."),
		strings.HasPrefix(kind, "access.policy."):
		return CatChanges
	case strings.HasPrefix(kind, "asset."):
		return CatChanges
	default:
		return ""
	}
}

func IsPrivileged(source, kind string) bool {
	if strings.ToLower(strings.TrimSpace(source)) == "session" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "access.breakglass.opened", "session.admin_bypass", "access.request.approved":
		return true
	default:
		return false
	}
}

func (s *ReportSummary) add(cat string, n int) {
	if n <= 0 {
		return
	}
	switch cat {
	case CatAccess:
		s.Access += n
	case CatPrivileged:
		s.Privileged += n
	case CatApprovals:
		s.Approvals += n
	case CatConnections:
		s.Connections += n
	case CatCommands:
		s.Commands += n
	case CatSQL:
		s.SQL += n
	case CatDownloads:
		s.Downloads += n
	case CatChanges:
		s.Changes += n
	case CatRevoked:
		s.Revoked += n
	}
}

func reportNotes() []string {
	return []string{
		"Команды SSH: в evidence попадают JEA deny, k8s и HTTP ACL — не полный shell-транскрипт (asciicast вне scope).",
		"SQL: разрешённые и запрещённые statements из session_events.",
		"Framework задаёт подписи контролей (ISO A.9 / PCI 7–10 / SOC2 CC6–CC7 / NIST AC,AU,CM), не разные выборки.",
		"Snapshot — live ACL/сессии/JIT/break-glass на момент генерации, не за период.",
	}
}

func (s *Service) Report(ctx context.Context, actorID uuid.UUID, in ReportInput, ip, ua string) (Report, error) {
	from, to, err := ParseReportWindow(in.From, in.To, in.Days, time.Now().UTC())
	if err != nil {
		return Report{}, err
	}
	fw := NormalizeFramework(in.Framework)
	limit := in.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	snap, err := s.reportSnapshot(ctx)
	if err != nil {
		return Report{}, err
	}
	summary, total, err := s.reportCounts(ctx, from, to)
	if err != nil {
		return Report{}, err
	}
	evidence, err := s.reportEvidence(ctx, from, to, limit)
	if err != nil {
		return Report{}, err
	}
	if evidence == nil {
		evidence = []EvidenceRow{}
	}

	rep := Report{
		GeneratedAt:   time.Now().UTC(),
		From:          from,
		To:            to,
		Framework:     fw,
		Controls:      FrameworkControls(fw),
		Summary:       summary,
		Snapshot:      snap,
		Evidence:      evidence,
		EvidenceTotal: total,
		Truncated:     total > len(evidence),
		Notes:         reportNotes(),
	}
	_ = s.aud.Record(ctx, &actorID, "compliance.report.generated", "compliance_report", fw, ip, ua, map[string]any{
		"from": from, "to": to, "framework": fw, "evidence_total": total, "truncated": rep.Truncated,
	})
	return rep, nil
}

func (s *Service) reportSnapshot(ctx context.Context) (ReportSnapshot, error) {
	var snap ReportSnapshot
	err := s.db.Pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM asset_access_bindings WHERE expires_at IS NULL OR expires_at > NOW()),
			(SELECT COUNT(*) FROM sessions WHERE status IN ('pending','active')),
			(SELECT COUNT(*) FROM access_requests WHERE status='pending'),
			(SELECT COUNT(*) FROM break_glass_events WHERE closed_at IS NULL AND expires_at > NOW()),
			(SELECT COUNT(*) FROM legal_holds WHERE active=TRUE)
	`).Scan(&snap.ACLLive, &snap.SessionsActive, &snap.JITPending, &snap.BreakGlassActive, &snap.LegalHolds)
	return snap, err
}

func (s *Service) reportCounts(ctx context.Context, from, to time.Time) (ReportSummary, int, error) {
	var sum ReportSummary
	total := 0

	rows, err := s.db.Pool.Query(ctx, `
		SELECT action, COUNT(*) FROM audit_events
		WHERE ts >= $1 AND ts <= $2
		GROUP BY action`, from, to)
	if err != nil {
		return sum, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var action string
		var n int
		if err := rows.Scan(&action, &n); err != nil {
			return sum, 0, err
		}
		cat := EvidenceCategory("audit", action)
		if cat == "" {
			continue
		}
		sum.add(cat, n)
		if IsPrivileged("audit", action) && cat != CatPrivileged {
			sum.add(CatPrivileged, n)
		}
		total += n
	}
	if err := rows.Err(); err != nil {
		return sum, 0, err
	}

	srows, err := s.db.Pool.Query(ctx, `
		SELECT event_type, COUNT(*) FROM session_events
		WHERE ts >= $1 AND ts <= $2
		GROUP BY event_type`, from, to)
	if err != nil {
		return sum, 0, err
	}
	defer srows.Close()
	for srows.Next() {
		var kind string
		var n int
		if err := srows.Scan(&kind, &n); err != nil {
			return sum, 0, err
		}
		cat := EvidenceCategory("session", kind)
		if cat == "" {
			continue
		}
		sum.add(cat, n)
		total += n
	}
	return sum, total, srows.Err()
}

func (s *Service) reportEvidence(ctx context.Context, from, to time.Time, limit int) ([]EvidenceRow, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, ts, source, kind, actor, resource_type, resource_id, ip, payload FROM (
			SELECT ae.id, ae.ts, 'audit'::text AS source, ae.action AS kind,
				COALESCE(u.username,'') AS actor,
				ae.resource_type, ae.resource_id, ae.ip, ae.payload
			FROM audit_events ae
			LEFT JOIN users u ON u.id = ae.actor_id
			WHERE ae.ts >= $1 AND ae.ts <= $2
			UNION ALL
			SELECT e.id, e.ts, 'session'::text AS source, e.event_type AS kind,
				COALESCE(u.username,'') AS actor,
				'session'::text, s.id::text, COALESCE(s.client_ip,''), e.payload
			FROM session_events e
			JOIN sessions s ON s.id = e.session_id
			JOIN users u ON u.id = s.user_id
			WHERE e.ts >= $1 AND e.ts <= $2
			  AND e.event_type IN ('sql','sql_denied','command_denied','command','k8s','http_denied','app_denied','app_approval','dlp','created','started','ended')
		) x
		ORDER BY ts DESC, id DESC
		LIMIT $3`, from, to, limit*4)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]EvidenceRow, 0, limit)
	for rows.Next() {
		var ev EvidenceRow
		var raw []byte
		if err := rows.Scan(&ev.ID, &ev.TS, &ev.Source, &ev.Action, &ev.Actor, &ev.ResourceType, &ev.ResourceID, &ev.IP, &raw); err != nil {
			return nil, err
		}
		ev.Category = EvidenceCategory(ev.Source, ev.Action)
		if ev.Category == "" {
			continue
		}
		var payload map[string]any
		_ = json.Unmarshal(raw, &payload)
		ev.Detail = evidenceDetail(ev.Source, ev.Action, ev.ResourceType, ev.ResourceID, payload)
		ev.TS = ev.TS.UTC()
		out = append(out, ev)
		if len(out) >= limit {
			break
		}
	}
	return out, rows.Err()
}

func evidenceDetail(source, kind, resourceType, resourceID string, payload map[string]any) string {
	if payload != nil {
		for _, k := range []string{"reason", "statement", "command", "name", "verb", "path", "method"} {
			if v := payloadString(payload, k); v != "" {
				if len(v) > 240 {
					v = v[:240] + "…"
				}
				return kind + ": " + v
			}
		}
	}
	res := strings.TrimSpace(resourceType + " " + resourceID)
	if res != "" {
		return strings.TrimSpace(kind + " " + res)
	}
	_ = source
	return kind
}

func payloadString(payload map[string]any, key string) string {
	if payload == nil {
		return ""
	}
	v, ok := payload[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func WriteReportCSV(w io.Writer, rep Report) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"ts", "category", "source", "actor", "action", "resource_type", "resource_id", "detail", "ip"}); err != nil {
		return err
	}
	for _, e := range rep.Evidence {
		if err := cw.Write([]string{
			e.TS.UTC().Format(time.RFC3339Nano),
			e.Category,
			e.Source,
			e.Actor,
			e.Action,
			e.ResourceType,
			e.ResourceID,
			e.Detail,
			e.IP,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
