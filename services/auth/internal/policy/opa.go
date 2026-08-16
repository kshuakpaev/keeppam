package policy

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/rego"
)

const defaultOPAPackage = "keeppam.authz"

var opaPackageRe = regexp.MustCompile(`(?m)^package\s+([A-Za-z0-9_.]+)`)

type Engine struct {
	path     string
	pkg      string
	query    string
	prepared rego.PreparedEvalQuery
}

func (e *Engine) Path() string {
	if e == nil {
		return ""
	}
	return e.path
}

func (e *Engine) Package() string {
	if e == nil {
		return ""
	}
	return e.pkg
}

func (e *Engine) Ready() bool { return e != nil }

func LoadOPA(path string) (*Engine, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opa policy: %w", err)
	}
	eng, err := CompileOPA(string(raw))
	if err != nil {
		return nil, err
	}
	eng.path = path
	return eng, nil
}

func CompileOPA(src string) (*Engine, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return nil, fmt.Errorf("opa policy is empty")
	}
	pkg := defaultOPAPackage
	if m := opaPackageRe.FindStringSubmatch(src); len(m) == 2 {
		pkg = m[1]
	}
	q := "data." + pkg + ".deny"
	r := rego.New(
		rego.Query(q),
		rego.Module("keeppam.rego", src),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("opa compile: %w", err)
	}
	return &Engine{pkg: pkg, query: q, prepared: pq}, nil
}

func (e *Engine) Deny(ctx context.Context, input any) (bool, string, error) {
	if e == nil {
		return false, "", nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	rs, err := e.prepared.Eval(c, rego.EvalInput(input))
	if err != nil {
		return true, "eval_error", err
	}
	return interpretDeny(rs)
}

func interpretDeny(rs rego.ResultSet) (bool, string, error) {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return false, "", nil
	}
	v := rs[0].Expressions[0].Value
	switch t := v.(type) {
	case bool:
		return t, "", nil
	case string:
		return t != "", t, nil
	case []any:
		if len(t) == 0 {
			return false, "", nil
		}
		return true, joinOPAReasons(t), nil
	case map[string]any:
		if len(t) == 0 {
			return false, "", nil
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return true, strings.Join(keys, "; "), nil
	default:
		return false, "", nil
	}
}

func joinOPAReasons(in []any) string {
	var parts []string
	for _, x := range in {
		switch t := x.(type) {
		case string:
			if t != "" {
				parts = append(parts, t)
			}
		default:
			parts = append(parts, fmt.Sprint(t))
		}
	}
	return strings.Join(parts, "; ")
}

func (s *Service) SetOPA(e *Engine) { s.opa = e }

func (s *Service) OPA() *Engine { return s.opa }

func (s *Service) applyOPA(ctx context.Context, in AccessCheck, userTags []string, res *AccessResult) {
	if s.opa == nil || res == nil || !res.OK || in.Bypass {
		return
	}
	input := s.opaInput(ctx, in, userTags, res)
	denied, reason, err := s.opa.Deny(ctx, input)
	if err != nil {
		res.OK = false
		res.DeniedByOPA = true
		res.OPAReason = "eval_error"
		payload := map[string]any{"reason": "eval_error", "error": truncateOPAErr(err.Error())}
		if res.BindingID != nil {
			payload["binding_id"] = res.BindingID.String()
		}
		_ = s.aud.Record(ctx, &in.UserID, "access.opa.denied", "asset", in.AssetID.String(), in.ClientIP, "", payload)
		return
	}
	if !denied {
		return
	}
	res.OK = false
	res.DeniedByOPA = true
	res.OPAReason = reason
	payload := map[string]any{"reason": reason}
	if res.BindingID != nil {
		payload["binding_id"] = res.BindingID.String()
	}
	_ = s.aud.Record(ctx, &in.UserID, "access.opa.denied", "asset", in.AssetID.String(), in.ClientIP, "", payload)
}

func (s *Service) opaInput(ctx context.Context, in AccessCheck, userTags []string, res *AccessResult) map[string]any {
	if in.ClientCountry == "" {
		in.ClientCountry = s.ClientCountry(in.ClientIP)
	}
	username := ""
	_ = s.db.Pool.QueryRow(ctx, `SELECT username FROM users WHERE id=$1`, in.UserID).Scan(&username)
	groupNames, _ := s.userGroupNames(ctx, in.UserID)
	if groupNames == nil {
		groupNames = []string{}
	}
	var name, assetType, proto string
	_ = s.db.Pool.QueryRow(ctx, `SELECT name, COALESCE(asset_type,''), protocol FROM assets WHERE id=$1`, in.AssetID).Scan(&name, &assetType, &proto)
	assetTags, _ := s.assetTags(ctx, in.AssetID)
	binding := map[string]any{}
	if res.BindingID != nil {
		binding["id"] = res.BindingID.String()
	}
	if res.AccessPolicyID != nil {
		binding["access_policy_id"] = res.AccessPolicyID.String()
	}
	if res.GroupID != nil {
		binding["group_id"] = res.GroupID.String()
	}
	if res.HTTPPolicyPackID != nil {
		binding["http_policy_pack_id"] = res.HTTPPolicyPackID.String()
	}
	if res.AppObjectPackID != nil {
		binding["app_object_pack_id"] = res.AppObjectPackID.String()
	}
	binding["tag_acl"] = res.TagACL
	if res.MatchTags == nil {
		binding["asset_match_tags"] = []string{}
	} else {
		binding["asset_match_tags"] = res.MatchTags
	}
	if res.MatchMode != "" {
		binding["asset_match_mode"] = res.MatchMode
	}
	binding["max_risk"] = res.MaxRisk
	binding["risk_action"] = res.RiskAction
	if res.AllowedNamespaces == nil {
		binding["allowed_namespaces"] = []string{}
	} else {
		binding["allowed_namespaces"] = res.AllowedNamespaces
	}
	if res.AllowedEgress == nil {
		binding["allowed_egress"] = []string{}
	} else {
		binding["allowed_egress"] = res.AllowedEgress
	}
	if userTags == nil {
		userTags = []string{}
	}
	if assetTags == nil {
		assetTags = []string{}
	}
	userTags = expandTagAncestors(userTags)
	assetTags = expandTagAncestors(assetTags)
	devices := in.ClientDevices
	if devices == nil {
		devices = []string{}
	}
	factors := res.RiskFactors
	if factors == nil {
		factors = []string{}
	}
	roles := in.RoleNames
	if roles == nil {
		roles = []string{}
	}
	return map[string]any{
		"user": map[string]any{
			"id":       in.UserID.String(),
			"username": username,
			"roles":    roles,
			"groups":   groupNames,
			"tags":     userTags,
		},
		"asset": map[string]any{
			"id":       in.AssetID.String(),
			"name":     name,
			"type":     assetType,
			"protocol": proto,
			"tags":     assetTags,
		},
		"binding": binding,
		"request": map[string]any{
			"ticket_id":      strings.TrimSpace(in.TicketID),
			"reason":         strings.TrimSpace(in.Reason),
			"client_ip":      in.ClientIP,
			"client_country": in.ClientCountry,
			"client_devices": devices,
			"risk_score":     res.RiskScore,
			"risk_factors":   factors,
			"operation":      strings.TrimSpace(in.Operation),
		},
	}
}

func truncateOPAErr(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
