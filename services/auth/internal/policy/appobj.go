package policy

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/store"
)

type AppObjectPack struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Unmatched   string    `json:"unmatched"` // allow|deny
	Rules       []string  `json:"rules"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AppObjectPackInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Unmatched   string   `json:"unmatched"`
	Rules       []string `json:"rules"`
}

type AppObjectDecision struct {
	Allowed  bool   `json:"allowed"`
	Matched  bool   `json:"matched"`
	Object   string `json:"object,omitempty"`
	Action   string `json:"action"` // allow|deny|approval
	Reason   string `json:"reason,omitempty"`
	Code     string   `json:"code,omitempty"` // approval_required | app_denied
	PackName string   `json:"pack_name,omitempty"`
	GraphQL  []string `json:"graphql_fields,omitempty"`
}

type AppObjectPreviewInput struct {
	PackID    *uuid.UUID `json:"pack_id"`
	Method    string     `json:"method"`
	Path      string     `json:"path"`
	Query     string     `json:"query"`
	Rules     []string   `json:"rules"`
	Unmatched string     `json:"unmatched"`
}

var appObjectNameRe = regexp.MustCompile(`^(\*|[a-z_*][a-z0-9_.*-]{0,63})$`)

func (s *Service) ListAppObjectPacks(ctx context.Context) ([]AppObjectPack, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, unmatched, rules, created_at, updated_at
		FROM app_object_packs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppObjectPack
	for rows.Next() {
		p, err := scanAppObjectPack(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []AppObjectPack{}
	}
	return out, rows.Err()
}

func (s *Service) GetAppObjectPack(ctx context.Context, id uuid.UUID) (AppObjectPack, error) {
	row := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, unmatched, rules, created_at, updated_at
		FROM app_object_packs WHERE id=$1`, id)
	return scanAppObjectPack(row)
}

func (s *Service) CreateAppObjectPack(ctx context.Context, actorID uuid.UUID, in AppObjectPackInput, ip, ua string) (AppObjectPack, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return AppObjectPack{}, fmt.Errorf("name required")
	}
	unmatched, err := normalizeUnmatched(in.Unmatched)
	if err != nil {
		return AppObjectPack{}, err
	}
	rules, err := normalizeAppObjectRules(in.Rules)
	if err != nil {
		return AppObjectPack{}, err
	}
	id := store.NewID()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO app_object_packs (id, name, description, unmatched, rules, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,NOW(),NOW())`,
		id, name, strings.TrimSpace(in.Description), unmatched, rules)
	if err != nil {
		return AppObjectPack{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "jea.app_object_pack.created", "app_object_pack", id.String(), ip, ua, map[string]any{
		"name": name, "unmatched": unmatched, "rules": rules,
	})
	return s.GetAppObjectPack(ctx, id)
}

func (s *Service) UpdateAppObjectPack(ctx context.Context, actorID, id uuid.UUID, in AppObjectPackInput, ip, ua string) (AppObjectPack, error) {
	cur, err := s.GetAppObjectPack(ctx, id)
	if err != nil {
		return AppObjectPack{}, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = cur.Name
	}
	unmatched := strings.TrimSpace(in.Unmatched)
	if unmatched == "" {
		unmatched = cur.Unmatched
	}
	unmatched, err = normalizeUnmatched(unmatched)
	if err != nil {
		return AppObjectPack{}, err
	}
	rules := cur.Rules
	if in.Rules != nil {
		rules, err = normalizeAppObjectRules(in.Rules)
		if err != nil {
			return AppObjectPack{}, err
		}
	}
	desc := in.Description
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE app_object_packs SET name=$2, description=$3, unmatched=$4, rules=$5, updated_at=NOW()
		WHERE id=$1`, id, name, desc, unmatched, rules)
	if err != nil {
		return AppObjectPack{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "jea.app_object_pack.updated", "app_object_pack", id.String(), ip, ua, map[string]any{
		"name": name, "unmatched": unmatched,
	})
	return s.GetAppObjectPack(ctx, id)
}

func (s *Service) DeleteAppObjectPack(ctx context.Context, actorID, id uuid.UUID, ip, ua string) error {
	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM app_object_packs WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return s.aud.Record(ctx, &actorID, "jea.app_object_pack.deleted", "app_object_pack", id.String(), ip, ua, nil)
}

func (s *Service) PreviewAppObject(ctx context.Context, in AppObjectPreviewInput) (AppObjectDecision, error) {
	pack := AppObjectPack{Name: "inline", Unmatched: "allow", Rules: in.Rules}
	if in.Unmatched != "" {
		u, err := normalizeUnmatched(in.Unmatched)
		if err != nil {
			return AppObjectDecision{}, err
		}
		pack.Unmatched = u
	}
	if in.PackID != nil {
		p, err := s.GetAppObjectPack(ctx, *in.PackID)
		if err != nil {
			return AppObjectDecision{}, err
		}
		pack = p
	} else if in.Rules != nil {
		rules, err := normalizeAppObjectRules(in.Rules)
		if err != nil {
			return AppObjectDecision{}, err
		}
		pack.Rules = rules
	}
	d := MatchAppObjectFields(pack, in.Method, in.Path, previewGraphQLFields(in.Query))
	d.PackName = pack.Name
	return d, nil
}

func previewGraphQLFields(query string) []string {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	ct := "application/graphql"
	if strings.HasPrefix(query, "{") || strings.HasPrefix(query, "[") {
		ct = "application/json"
	}
	f, ok := ExtractGraphQLFields(ct, []byte(query))
	if !ok {
		f, ok = ExtractGraphQLFields("application/graphql", []byte(query))
	}
	if !ok {
		return nil
	}
	if f == nil {
		return []string{}
	}
	return f
}

func scanAppObjectPack(row scannable) (AppObjectPack, error) {
	var p AppObjectPack
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Unmatched, &p.Rules, &p.CreatedAt, &p.UpdatedAt)
	if p.Rules == nil {
		p.Rules = []string{}
	}
	if p.Unmatched == "" {
		p.Unmatched = "allow"
	}
	return p, err
}

func normalizeUnmatched(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "allow", nil
	}
	if s != "allow" && s != "deny" {
		return "", fmt.Errorf("unmatched must be allow or deny")
	}
	return s, nil
}

func normalizeAppObjectRules(in []string) ([]string, error) {
	var out []string
	seen := map[string]struct{}{}
	for _, raw := range in {
		r, ok := parseAppObjectRule(raw)
		if !ok {
			continue
		}
		line := r.Method + " " + r.Path + " " + r.Object + " " + r.Action
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	if out == nil {
		return []string{}, nil
	}
	return out, nil
}

type appObjectRule struct {
	Method, Path, Object, Action string
}

func parseAppObjectRule(raw string) (appObjectRule, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return appObjectRule{}, false
	}
	fields := strings.Fields(raw)
	if len(fields) != 4 {
		return appObjectRule{}, false
	}
	method := strings.ToUpper(fields[0])
	if method != "*" && !isHTTPMethod(method) {
		return appObjectRule{}, false
	}
	obj := strings.ToLower(fields[2])
	if !appObjectNameRe.MatchString(obj) {
		return appObjectRule{}, false
	}
	action := strings.ToLower(fields[3])
	if action != "allow" && action != "deny" && action != "approval" {
		return appObjectRule{}, false
	}
	return appObjectRule{
		Method: method,
		Path:   normalizeHTTPPattern(fields[1]),
		Object: obj,
		Action: action,
	}, true
}

// MatchAppObject maps method+path to a named application object.
// First matching rule wins. Without a pack the caller should skip this check.
func MatchAppObject(pack AppObjectPack, method, rawPath string) AppObjectDecision {
	return MatchAppObjectFields(pack, method, rawPath, nil)
}

// MatchAppObjectFields is MatchAppObject plus GraphQL top-level fields.
// gqlFields == nil means not a GraphQL request (REST: OBJECT is a label).
// Non-nil (even empty) means GraphQL: each field is matched; deny/approval
// on any field wins so a denied field cannot ride along with an allowed one.
func MatchAppObjectFields(pack AppObjectPack, method, rawPath string, gqlFields []string) AppObjectDecision {
	if gqlFields == nil {
		return matchAppObjectREST(pack, method, rawPath)
	}
	return matchAppObjectGraphQL(pack, method, rawPath, gqlFields)
}

func matchAppObjectREST(pack AppObjectPack, method, rawPath string) AppObjectDecision {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	p := normalizeRequestPath(rawPath)
	unmatched := pack.Unmatched
	if unmatched != "deny" {
		unmatched = "allow"
	}
	for _, raw := range pack.Rules {
		r, ok := parseAppObjectRule(raw)
		if !ok {
			continue
		}
		if !httpRuleMatches(method, p, r.Method, r.Path) {
			continue
		}
		return decisionFromRule(r, pack.Name)
	}
	if unmatched == "deny" {
		return AppObjectDecision{
			Allowed: false, Matched: false, Action: "deny", Code: "app_denied",
			Reason: "app object unmatched: " + method + " " + p, PackName: pack.Name,
		}
	}
	return AppObjectDecision{Allowed: true, Matched: false, Action: "allow", PackName: pack.Name}
}

func matchAppObjectGraphQL(pack AppObjectPack, method, rawPath string, fields []string) AppObjectDecision {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "POST"
	}
	p := normalizeRequestPath(rawPath)
	unmatched := pack.Unmatched
	if unmatched != "deny" {
		unmatched = "allow"
	}
	check := fields
	if len(check) == 0 {
		check = []string{""}
	}
	worst := AppObjectDecision{Allowed: true, Action: "allow", PackName: pack.Name, GraphQL: fields}
	worstRank := 0
	for _, f := range check {
		d := firstGraphQLObjectRule(pack, method, p, f)
		rank := 0
		if !d.Matched {
			if unmatched == "deny" {
				d = AppObjectDecision{
					Allowed: false, Matched: false, Action: "deny", Code: "app_denied",
					Reason: "app object unmatched graphql field: " + f, PackName: pack.Name,
					Object: f,
				}
				rank = 2
			}
		} else {
			switch d.Action {
			case "deny":
				rank = 2
			case "approval":
				rank = 1
			}
		}
		if rank > worstRank {
			worstRank = rank
			worst = d
			worst.GraphQL = fields
			worst.PackName = pack.Name
		}
	}
	return worst
}

func firstGraphQLObjectRule(pack AppObjectPack, method, path, field string) AppObjectDecision {
	for _, raw := range pack.Rules {
		r, ok := parseAppObjectRule(raw)
		if !ok {
			continue
		}
		if !httpRuleMatches(method, path, r.Method, r.Path) {
			continue
		}
		if !graphQLObjectMatches(r.Object, field) {
			continue
		}
		d := decisionFromRule(r, pack.Name)
		if field != "" {
			d.Object = field
		}
		return d
	}
	return AppObjectDecision{Allowed: true, Matched: false, Action: "allow", PackName: pack.Name}
}

func graphQLObjectMatches(object, field string) bool {
	if object == "*" {
		return true
	}
	field = strings.ToLower(strings.TrimSpace(field))
	if field == "" {
		return false
	}
	return matchHTTPPath(object, field)
}

func decisionFromRule(r appObjectRule, packName string) AppObjectDecision {
	d := AppObjectDecision{Matched: true, Object: r.Object, Action: r.Action, PackName: packName}
	switch r.Action {
	case "allow":
		d.Allowed = true
	case "approval":
		d.Allowed = false
		d.Code = "approval_required"
		d.Reason = "app object requires approval: " + r.Object
	default:
		d.Allowed = false
		d.Code = "app_denied"
		d.Reason = "app object denied: " + r.Object
	}
	return d
}
