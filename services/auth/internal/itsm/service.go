package itsm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/store"
)

type Settings struct {
	Enabled              bool       `json:"enabled"`
	Provider             string     `json:"provider"` // mock|generic|jira|servicenow
	BaseURL              string     `json:"base_url"`
	AuthHeader           string     `json:"auth_header,omitempty"` // write-only
	HasAuthHeader        bool       `json:"has_auth_header"`
	TicketPathTemplate   string     `json:"ticket_path_template"`
	StatusJSONPath       string     `json:"status_json_path"`
	OkStatuses           []string   `json:"ok_statuses"`
	RequireOnRequest     bool       `json:"require_on_request"`
	RequireOnApprove     bool       `json:"require_on_approve"`
	RequireOnConnect     bool       `json:"require_on_connect"`
	CacheTTLSec          int        `json:"cache_ttl_sec"`
	TimeoutSec           int        `json:"timeout_sec"`
	LastError            string     `json:"last_error,omitempty"`
	LastCheckAt          *time.Time `json:"last_check_at,omitempty"`
	UpdatedAt            *time.Time `json:"updated_at,omitempty"`
}

type TicketInfo struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	OK     bool   `json:"ok"`
	Cached bool   `json:"cached,omitempty"`
	Title  string `json:"title,omitempty"`
}

type Service struct {
	db  *store.DB
	aud *audit.Service
	env *crypto.Envelope
	rdb *redis.Client
}

func New(db *store.DB, aud *audit.Service, env *crypto.Envelope, rdb *redis.Client) *Service {
	return &Service{db: db, aud: aud, env: env, rdb: rdb}
}

func (s *Service) Get(ctx context.Context) (Settings, []byte, error) {
	var out Settings
	var authEnc []byte
	var updatedAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT enabled, provider, base_url, auth_header_enc, ticket_path_template, status_json_path,
			ok_statuses, require_on_request, require_on_approve, require_on_connect,
			cache_ttl_sec, timeout_sec, last_error, last_check_at, updated_at
		FROM itsm_settings WHERE id=1`).Scan(
		&out.Enabled, &out.Provider, &out.BaseURL, &authEnc, &out.TicketPathTemplate, &out.StatusJSONPath,
		&out.OkStatuses, &out.RequireOnRequest, &out.RequireOnApprove, &out.RequireOnConnect,
		&out.CacheTTLSec, &out.TimeoutSec, &out.LastError, &out.LastCheckAt, &updatedAt,
	)
	if err != nil {
		return Settings{}, nil, err
	}
	out.HasAuthHeader = len(authEnc) > 0
	out.UpdatedAt = &updatedAt
	if out.OkStatuses == nil {
		out.OkStatuses = []string{}
	}
	return out, authEnc, nil
}

func (s *Service) Update(ctx context.Context, actorID uuid.UUID, in Settings, ip, ua string) (Settings, error) {
	cur, authEnc, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	provider := strings.TrimSpace(in.Provider)
	if provider == "" {
		provider = "mock"
	}
	switch provider {
	case "mock", "generic", "jira", "servicenow":
	default:
		return Settings{}, fmt.Errorf("invalid provider")
	}
	pathTpl := strings.TrimSpace(in.TicketPathTemplate)
	if pathTpl == "" {
		pathTpl = defaultPath(provider)
	}
	statusPath := strings.TrimSpace(in.StatusJSONPath)
	if statusPath == "" {
		statusPath = defaultStatusPath(provider)
	}
	okStatuses := normalizeStatuses(in.OkStatuses)
	if len(okStatuses) == 0 {
		okStatuses = defaultOKStatuses(provider)
	}
	cacheTTL := in.CacheTTLSec
	if cacheTTL < 0 {
		cacheTTL = 0
	}
	if cacheTTL > 3600 {
		cacheTTL = 3600
	}
	timeout := in.TimeoutSec
	if timeout <= 0 {
		timeout = 8
	}
	if timeout > 60 {
		timeout = 60
	}
	if strings.TrimSpace(in.AuthHeader) != "" {
		enc, err := s.env.Encrypt([]byte(strings.TrimSpace(in.AuthHeader)))
		if err != nil {
			return Settings{}, err
		}
		authEnc = enc
	}
	enabled := in.Enabled
	if enabled && provider != "mock" && strings.TrimSpace(in.BaseURL) == "" && strings.TrimSpace(cur.BaseURL) == "" {
		return Settings{}, fmt.Errorf("base_url required for provider %s", provider)
	}
	baseURL := strings.TrimSpace(in.BaseURL)
	if baseURL == "" {
		baseURL = cur.BaseURL
	}

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE itsm_settings SET
			enabled=$2, provider=$3, base_url=$4, auth_header_enc=$5,
			ticket_path_template=$6, status_json_path=$7, ok_statuses=$8,
			require_on_request=$9, require_on_approve=$10, require_on_connect=$11,
			cache_ttl_sec=$12, timeout_sec=$13, updated_at=NOW(), updated_by=$14, last_error=''
		WHERE id=$1`,
		1, enabled, provider, baseURL, authEnc, pathTpl, statusPath, okStatuses,
		in.RequireOnRequest, in.RequireOnApprove, in.RequireOnConnect, cacheTTL, timeout, actorID)
	if err != nil {
		return Settings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "settings.itsm.updated", "itsm_settings", "1", ip, ua, map[string]any{
		"enabled": enabled, "provider": provider,
		"require_on_request": in.RequireOnRequest, "require_on_approve": in.RequireOnApprove,
		"require_on_connect": in.RequireOnConnect,
		"prev_enabled": cur.Enabled, "prev_provider": cur.Provider,
	})
	out, _, err := s.Get(ctx)
	return out, err
}

// Enforce applies ITSM gate for phase: request|approve|connect. No-op if disabled or phase not required.
func (s *Service) Enforce(ctx context.Context, phase, ticketID string) error {
	if s == nil {
		return nil
	}
	cfg, _, err := s.Get(ctx)
	if err != nil || !cfg.Enabled {
		return nil
	}
	need := false
	switch phase {
	case "request":
		need = cfg.RequireOnRequest
	case "approve":
		need = cfg.RequireOnApprove
	case "connect":
		need = cfg.RequireOnConnect
	default:
		return fmt.Errorf("unknown itsm phase")
	}
	if !need {
		return nil
	}
	ticketID = strings.TrimSpace(ticketID)
	if ticketID == "" {
		return fmt.Errorf("ticket_id required by ITSM gate (%s)", phase)
	}
	info, err := s.Validate(ctx, ticketID)
	if err != nil {
		return err
	}
	if !info.OK {
		return fmt.Errorf("ITSM ticket %s status %q is not allowed", info.ID, info.Status)
	}
	return nil
}

func (s *Service) Validate(ctx context.Context, ticketID string) (TicketInfo, error) {
	ticketID = strings.TrimSpace(ticketID)
	if ticketID == "" {
		return TicketInfo{}, fmt.Errorf("ticket_id required")
	}
	if len(ticketID) > 200 {
		return TicketInfo{}, fmt.Errorf("ticket_id too long")
	}
	cfg, authEnc, err := s.Get(ctx)
	if err != nil {
		return TicketInfo{}, err
	}
	if cached, ok := s.cacheGet(ctx, ticketID); ok {
		cached.Cached = true
		return cached, nil
	}
	authHeader, _ := s.decryptAuth(authEnc)
	info, err := s.fetchTicket(ctx, cfg, authHeader, ticketID)
	if err != nil {
		s.setError(ctx, err.Error())
		_ = s.aud.Record(ctx, nil, "itsm.ticket.rejected", "ticket", ticketID, "", "itsm", map[string]any{
			"error": err.Error(), "provider": cfg.Provider,
		})
		return TicketInfo{}, err
	}
	info.OK = statusAllowed(info.Status, cfg.OkStatuses)
	s.cacheSet(ctx, ticketID, info, cfg.CacheTTLSec)
	s.setCheckOK(ctx)
	action := "itsm.ticket.validated"
	if !info.OK {
		action = "itsm.ticket.rejected"
	}
	_ = s.aud.Record(ctx, nil, action, "ticket", ticketID, "", "itsm", map[string]any{
		"status": info.Status, "ok": info.OK, "provider": cfg.Provider, "title": info.Title,
	})
	return info, nil
}

func (s *Service) fetchTicket(ctx context.Context, cfg Settings, authHeader, ticketID string) (TicketInfo, error) {
	switch cfg.Provider {
	case "mock":
		return mockTicket(ticketID), nil
	case "jira":
		return s.httpTicket(ctx, cfg, authHeader, ticketID, joinURL(cfg.BaseURL, strings.ReplaceAll(defaultPath("jira"), "{ticket}", url.PathEscape(ticketID))), cfg.StatusJSONPath)
	case "servicenow":
		q := url.Values{}
		q.Set("sysparm_query", "number="+ticketID)
		q.Set("sysparm_limit", "1")
		q.Set("sysparm_fields", "number,state,short_description,incident_state")
		u := strings.TrimRight(cfg.BaseURL, "/") + "/api/now/table/incident?" + q.Encode()
		return s.httpTicket(ctx, cfg, authHeader, ticketID, u, "result.0.state")
	default: // generic
		path := cfg.TicketPathTemplate
		if path == "" {
			path = "/ticket/{ticket}"
		}
		path = strings.ReplaceAll(path, "{ticket}", url.PathEscape(ticketID))
		return s.httpTicket(ctx, cfg, authHeader, ticketID, joinURL(cfg.BaseURL, path), cfg.StatusJSONPath)
	}
}

func (s *Service) httpTicket(ctx context.Context, cfg Settings, authHeader, ticketID, fullURL, statusPath string) (TicketInfo, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" && !strings.HasPrefix(fullURL, "http") {
		return TicketInfo{}, fmt.Errorf("itsm base_url not configured")
	}
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return TicketInfo{}, err
	}
	req.Header.Set("Accept", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return TicketInfo{}, fmt.Errorf("itsm request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return TicketInfo{}, fmt.Errorf("ITSM ticket %s not found", ticketID)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		return TicketInfo{}, fmt.Errorf("ITSM HTTP %d: %s", resp.StatusCode, msg)
	}
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return TicketInfo{}, fmt.Errorf("itsm invalid json: %w", err)
	}
	status := strings.TrimSpace(lookupJSON(raw, statusPath))
	if status == "" {
		status = strings.TrimSpace(lookupJSON(raw, "status"))
	}
	if status == "" {
		return TicketInfo{}, fmt.Errorf("itsm status not found at path %q", statusPath)
	}
	title := lookupJSON(raw, "fields.summary")
	if title == "" {
		title = lookupJSON(raw, "result.0.short_description")
	}
	if title == "" {
		title = lookupJSON(raw, "title")
	}
	return TicketInfo{ID: ticketID, Status: status, Title: title}, nil
}

var mockTicketRe = regexp.MustCompile(`(?i)^[A-Z][A-Z0-9]+-\d+$`)

func mockTicket(id string) TicketInfo {
	up := strings.ToUpper(id)
	info := TicketInfo{ID: id, Status: "Open", Title: "mock ticket " + id}
	if strings.HasSuffix(up, "-CLOSED") || strings.HasSuffix(strings.ToUpper(id), "/CLOSED") {
		info.Status = "Closed"
		return info
	}
	if strings.Contains(up, "CLOSED") {
		info.Status = "Closed"
		return info
	}
	if !mockTicketRe.MatchString(id) {
		info.Status = "Unknown"
	}
	return info
}

func statusAllowed(status string, ok []string) bool {
	st := strings.TrimSpace(strings.ToLower(status))
	for _, o := range ok {
		if strings.TrimSpace(strings.ToLower(o)) == st {
			return true
		}
	}
	return false
}

func normalizeStatuses(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		k := strings.ToLower(s)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}
	return out
}

func defaultPath(provider string) string {
	switch provider {
	case "jira":
		return "/rest/api/2/issue/{ticket}"
	case "servicenow":
		return "/api/now/table/incident"
	default:
		return "/ticket/{ticket}"
	}
}

func defaultStatusPath(provider string) string {
	switch provider {
	case "jira":
		return "fields.status.name"
	case "servicenow":
		return "result.0.state"
	default:
		return "status"
	}
}

func defaultOKStatuses(provider string) []string {
	switch provider {
	case "servicenow":
		return []string{"1", "2", "3", "New", "In Progress", "On Hold", "Open"}
	default:
		return []string{"Open", "In Progress", "To Do", "New", "Assigned", "Work in Progress"}
	}
}

func joinURL(base, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

func lookupJSON(v any, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	cur := v
	for _, part := range strings.Split(path, ".") {
		if cur == nil {
			return ""
		}
		switch node := cur.(type) {
		case map[string]any:
			cur = node[part]
		case []any:
			idx := 0
			if _, err := fmt.Sscanf(part, "%d", &idx); err != nil {
				return ""
			}
			if idx < 0 || idx >= len(node) {
				return ""
			}
			cur = node[idx]
		default:
			return ""
		}
	}
	switch t := cur.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%.0f", t)
	case bool:
		return fmt.Sprintf("%v", t)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func (s *Service) decryptAuth(enc []byte) (string, error) {
	if len(enc) == 0 {
		return "", nil
	}
	b, err := s.env.Decrypt(enc)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func cacheKey(id string) string { return "keeppam:itsm:ticket:" + strings.ToLower(id) }

func (s *Service) cacheGet(ctx context.Context, id string) (TicketInfo, bool) {
	if s.rdb == nil {
		return TicketInfo{}, false
	}
	raw, err := s.rdb.Get(ctx, cacheKey(id)).Bytes()
	if err != nil {
		return TicketInfo{}, false
	}
	var info TicketInfo
	if json.Unmarshal(raw, &info) != nil {
		return TicketInfo{}, false
	}
	return info, true
}

func (s *Service) cacheSet(ctx context.Context, id string, info TicketInfo, ttlSec int) {
	if s.rdb == nil || ttlSec <= 0 {
		return
	}
	raw, _ := json.Marshal(info)
	_ = s.rdb.Set(ctx, cacheKey(id), raw, time.Duration(ttlSec)*time.Second).Err()
}

func (s *Service) setError(ctx context.Context, msg string) {
	if len(msg) > 500 {
		msg = msg[:500] + "…"
	}
	_, _ = s.db.Pool.Exec(ctx, `UPDATE itsm_settings SET last_error=$2, last_check_at=NOW() WHERE id=1`, 1, msg)
}

func (s *Service) setCheckOK(ctx context.Context) {
	_, _ = s.db.Pool.Exec(ctx, `UPDATE itsm_settings SET last_error='', last_check_at=NOW() WHERE id=1`, 1)
}
