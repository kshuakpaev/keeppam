package policy

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/store"
)

type HTTPPack struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Mode        string    `json:"mode"` // allowlist|denylist
	Rules       []string  `json:"rules"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type HTTPPackInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Mode        string   `json:"mode"`
	Rules       []string `json:"rules"`
}

func (s *Service) ListHTTPPacks(ctx context.Context) ([]HTTPPack, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, mode, rules, created_at, updated_at
		FROM http_policy_packs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HTTPPack
	for rows.Next() {
		p, err := scanHTTPPack(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []HTTPPack{}
	}
	return out, rows.Err()
}

func (s *Service) GetHTTPPack(ctx context.Context, id uuid.UUID) (HTTPPack, error) {
	row := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, mode, rules, created_at, updated_at
		FROM http_policy_packs WHERE id=$1`, id)
	return scanHTTPPack(row)
}

func (s *Service) CreateHTTPPack(ctx context.Context, actorID uuid.UUID, in HTTPPackInput, ip, ua string) (HTTPPack, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return HTTPPack{}, fmt.Errorf("name required")
	}
	mode := strings.TrimSpace(in.Mode)
	if mode == "" {
		mode = "allowlist"
	}
	if mode != "allowlist" && mode != "denylist" {
		return HTTPPack{}, fmt.Errorf("invalid mode")
	}
	rules := normalizeHTTPRules(in.Rules)
	id := store.NewID()
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO http_policy_packs (id, name, description, mode, rules, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,NOW(),NOW())`,
		id, name, strings.TrimSpace(in.Description), mode, rules)
	if err != nil {
		return HTTPPack{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "jea.http_pack.created", "http_policy_pack", id.String(), ip, ua, map[string]any{
		"name": name, "mode": mode, "rules": rules,
	})
	return s.GetHTTPPack(ctx, id)
}

func (s *Service) UpdateHTTPPack(ctx context.Context, actorID, id uuid.UUID, in HTTPPackInput, ip, ua string) (HTTPPack, error) {
	cur, err := s.GetHTTPPack(ctx, id)
	if err != nil {
		return HTTPPack{}, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = cur.Name
	}
	mode := strings.TrimSpace(in.Mode)
	if mode == "" {
		mode = cur.Mode
	}
	if mode != "allowlist" && mode != "denylist" {
		return HTTPPack{}, fmt.Errorf("invalid mode")
	}
	rules := normalizeHTTPRules(in.Rules)
	if in.Rules == nil {
		rules = cur.Rules
	}
	desc := in.Description
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE http_policy_packs SET name=$2, description=$3, mode=$4, rules=$5, updated_at=NOW()
		WHERE id=$1`, id, name, desc, mode, rules)
	if err != nil {
		return HTTPPack{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "jea.http_pack.updated", "http_policy_pack", id.String(), ip, ua, map[string]any{
		"name": name, "mode": mode,
	})
	return s.GetHTTPPack(ctx, id)
}

func (s *Service) DeleteHTTPPack(ctx context.Context, actorID, id uuid.UUID, ip, ua string) error {
	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM http_policy_packs WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return s.aud.Record(ctx, &actorID, "jea.http_pack.deleted", "http_policy_pack", id.String(), ip, ua, nil)
}

func scanHTTPPack(row scannable) (HTTPPack, error) {
	var p HTTPPack
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.Rules, &p.CreatedAt, &p.UpdatedAt)
	if p.Rules == nil {
		p.Rules = []string{}
	}
	return p, err
}

func normalizeHTTPRules(in []string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, raw := range in {
		method, pathPat, ok := parseHTTPRule(raw)
		if !ok {
			continue
		}
		rule := method + " " + pathPat
		if _, dup := seen[rule]; dup {
			continue
		}
		seen[rule] = struct{}{}
		out = append(out, rule)
	}
	if out == nil {
		return []string{}
	}
	return out
}

func parseHTTPRule(raw string) (method, pathPat string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	fields := strings.Fields(raw)
	if len(fields) == 1 {
		return "*", normalizeHTTPPattern(fields[0]), true
	}
	method = strings.ToUpper(fields[0])
	if method != "*" && !isHTTPMethod(method) {
		return "", "", false
	}
	return method, normalizeHTTPPattern(fields[1]), true
}

func isHTTPMethod(m string) bool {
	switch m {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT":
		return true
	default:
		return false
	}
}

func normalizeHTTPPattern(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "*" {
		return "*"
	}
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if !strings.HasPrefix(p, "/") && p != "*" {
		p = "/" + p
	}
	return p
}

func normalizeRequestPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		raw = u.Path
	} else if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	if raw == "" {
		return "/"
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	return raw
}

// MatchHTTP reports whether method+path is allowed by the pack.
// Query string is ignored. Empty allowlist denies all; empty denylist allows all.
func MatchHTTP(pack HTTPPack, method, rawPath string) (bool, string) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	p := normalizeRequestPath(rawPath)
	if pack.Mode == "denylist" {
		for _, r := range pack.Rules {
			rm, rp, ok := parseHTTPRule(r)
			if !ok {
				continue
			}
			if httpRuleMatches(method, p, rm, rp) {
				return false, "http denied by ACL: " + method + " " + p
			}
		}
		return true, ""
	}
	if len(pack.Rules) == 0 {
		return false, "http JEA allowlist is empty"
	}
	for _, r := range pack.Rules {
		rm, rp, ok := parseHTTPRule(r)
		if !ok {
			continue
		}
		if httpRuleMatches(method, p, rm, rp) {
			return true, ""
		}
	}
	return false, "http not allowed by ACL: " + method + " " + p
}

func httpRuleMatches(method, path, ruleMethod, rulePath string) bool {
	if ruleMethod != "*" && ruleMethod != method {
		return false
	}
	return matchHTTPPath(rulePath, path)
}

var httpGlobCache sync.Map // string -> *regexp.Regexp

func matchHTTPPath(pattern, p string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == "*" || pattern == "/**" || pattern == "/*" {
		return true
	}
	re, err := httpGlob(pattern)
	if err != nil {
		return pattern == p
	}
	return re.MatchString(p)
}

func httpGlob(pattern string) (*regexp.Regexp, error) {
	if v, ok := httpGlobCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, err
	}
	httpGlobCache.Store(pattern, re)
	return re, nil
}
