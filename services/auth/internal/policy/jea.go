package policy

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/device"
	"github.com/keeppam/auth/internal/geoip"
	"github.com/keeppam/auth/internal/store"
)

type CommandPack struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Mode        string    `json:"mode"` // allowlist|denylist
	Patterns    []string  `json:"patterns"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CommandPackInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Mode        string   `json:"mode"`
	Patterns    []string `json:"patterns"`
}

type AccessResult struct {
	OK                  bool
	DeniedByRisk        bool
	DeniedByOPA         bool
	OPAReason           string
	BindingID           *uuid.UUID
	GroupID             *uuid.UUID
	CommandPolicyPackID *uuid.UUID
	SQLPolicyPackID     *uuid.UUID
	HTTPPolicyPackID    *uuid.UUID
	AppObjectPackID     *uuid.UUID
	AccessPolicyID      *uuid.UUID
	AllowedNamespaces   []string
	AllowedEgress       []string
	RiskScore           int
	MaxRisk             int
	RiskAction          string
	RiskFactors         []string
	Operation           string
	TagACL              bool
	MatchTags           []string
	MatchMode           string
	PIIAction           string
}

func (s *Service) ListCommandPacks(ctx context.Context) ([]CommandPack, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, mode, patterns, created_at, updated_at
		FROM command_policy_packs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CommandPack
	for rows.Next() {
		var p CommandPack
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.Patterns, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		if p.Patterns == nil {
			p.Patterns = []string{}
		}
		out = append(out, p)
	}
	if out == nil {
		out = []CommandPack{}
	}
	return out, rows.Err()
}

func (s *Service) GetCommandPack(ctx context.Context, id uuid.UUID) (CommandPack, error) {
	var p CommandPack
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, mode, patterns, created_at, updated_at
		FROM command_policy_packs WHERE id=$1`, id).Scan(
		&p.ID, &p.Name, &p.Description, &p.Mode, &p.Patterns, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return CommandPack{}, err
	}
	if p.Patterns == nil {
		p.Patterns = []string{}
	}
	return p, nil
}

func (s *Service) CreateCommandPack(ctx context.Context, actorID uuid.UUID, in CommandPackInput, ip, ua string) (CommandPack, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return CommandPack{}, fmt.Errorf("name required")
	}
	mode := strings.TrimSpace(in.Mode)
	if mode == "" {
		mode = "allowlist"
	}
	if mode != "allowlist" && mode != "denylist" {
		return CommandPack{}, fmt.Errorf("invalid mode")
	}
	patterns := normalizePatterns(in.Patterns)
	id := store.NewID()
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO command_policy_packs (id, name, description, mode, patterns, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,NOW(),NOW())`, id, name, strings.TrimSpace(in.Description), mode, patterns)
	if err != nil {
		return CommandPack{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "jea.pack.created", "command_policy_pack", id.String(), ip, ua, map[string]any{
		"name": name, "mode": mode, "patterns": patterns,
	})
	return s.GetCommandPack(ctx, id)
}

func (s *Service) UpdateCommandPack(ctx context.Context, actorID, id uuid.UUID, in CommandPackInput, ip, ua string) (CommandPack, error) {
	cur, err := s.GetCommandPack(ctx, id)
	if err != nil {
		return CommandPack{}, err
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
		return CommandPack{}, fmt.Errorf("invalid mode")
	}
	patterns := normalizePatterns(in.Patterns)
	if in.Patterns == nil {
		patterns = cur.Patterns
	}
	desc := in.Description
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE command_policy_packs SET name=$2, description=$3, mode=$4, patterns=$5, updated_at=NOW()
		WHERE id=$1`, id, name, desc, mode, patterns)
	if err != nil {
		return CommandPack{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "jea.pack.updated", "command_policy_pack", id.String(), ip, ua, map[string]any{
		"name": name, "mode": mode,
	})
	return s.GetCommandPack(ctx, id)
}

func (s *Service) DeleteCommandPack(ctx context.Context, actorID, id uuid.UUID, ip, ua string) error {
	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM command_policy_packs WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return s.aud.Record(ctx, &actorID, "jea.pack.deleted", "command_policy_pack", id.String(), ip, ua, nil)
}

func normalizePatterns(in []string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if out == nil {
		return []string{}
	}
	return out
}

// MatchCommand returns true if the command line is allowed by the pack.
func MatchCommand(pack CommandPack, line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return true
	}
	p := ParseCommand(line)
	candidates := []string{p.Raw, p.Inner, p.Binary}
	matched := false
	for _, pat := range pack.Patterns {
		for _, cand := range candidates {
			if cand == "" {
				continue
			}
			if matchPattern(pat, cand) {
				matched = true
				break
			}
		}
		if matched {
			break
		}
	}
	if pack.Mode == "denylist" {
		return !matched
	}
	return matched
}

func matchPattern(pattern, line string) bool {
	pattern = strings.TrimSpace(pattern)
	line = strings.TrimSpace(line)
	if pattern == "" {
		return false
	}
	// case-insensitive via lower
	pl := strings.ToLower(pattern)
	ll := strings.ToLower(line)
	ok, err := path.Match(pl, ll)
	if err != nil {
		return pl == ll
	}
	if ok {
		return true
	}
	// also match first token for patterns without wildcard like "ls"
	if !strings.ContainsAny(pl, "*?[") {
		fields := strings.Fields(ll)
		if len(fields) > 0 && fields[0] == pl {
			return true
		}
	}
	return false
}

// Evaluate returns access decision including matched binding's JEA pack.
func (s *Service) Evaluate(ctx context.Context, in AccessCheck) (AccessResult, error) {
	if in.Bypass {
		return AccessResult{OK: true}, nil
	}
	if len(in.ClientDevices) == 0 {
		in.ClientDevices = DevicesFrom(ctx)
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	userTags, err := s.UserTags(ctx, in.UserID)
	if err != nil {
		return AccessResult{}, err
	}
	assetTags, err := s.assetTags(ctx, in.AssetID)
	if err != nil {
		return AccessResult{}, err
	}
	userTagSet := toSet(expandTagAncestors(userTags))
	assetTags = expandTagAncestors(assetTags)
	assetTagSet := toSet(assetTags)
	ticket := strings.TrimSpace(in.TicketID)

	in.Now = now
	rows, err := s.db.Pool.Query(ctx, `
		SELECT b.id, b.user_id, b.role_id, b.group_id, b.time_start, b.time_end, b.days_of_week, b.expires_at,
			b.required_tags, b.require_ticket, COALESCE(b.require_reason,false), COALESCE(b.allowed_cidrs,'{}'),
			COALESCE(b.allowed_countries,'{}'), COALESCE(b.allowed_devices,'{}'),
			COALESCE(b.allowed_namespaces,'{}'), COALESCE(b.allowed_egress,'{}'),
			b.command_policy_pack_id, b.sql_policy_pack_id, b.http_policy_pack_id, b.app_object_pack_id, r.name,
			COALESCE(b.max_risk,0), COALESCE(b.risk_action,'deny'), COALESCE(b.pii_action,''),
			b.access_policy_id,
			p.time_start, p.time_end, COALESCE(p.days_of_week, 127),
			COALESCE(p.required_tags,'{}'), COALESCE(p.require_ticket,false), COALESCE(p.require_reason,false),
			COALESCE(p.allowed_cidrs,'{}'), COALESCE(p.allowed_countries,'{}'), COALESCE(p.allowed_devices,'{}'),
			COALESCE(p.allowed_namespaces,'{}'), COALESCE(p.allowed_egress,'{}'),
			p.command_policy_pack_id, p.sql_policy_pack_id, p.http_policy_pack_id, p.app_object_pack_id,
			COALESCE(p.max_risk,0), COALESCE(p.risk_action,'deny'), COALESCE(p.pii_action,''),
			b.asset_id, COALESCE(b.asset_match_tags,'{}'), COALESCE(b.asset_match_mode,'all')
		FROM asset_access_bindings b
		LEFT JOIN roles r ON r.id = b.role_id
		LEFT JOIN access_policies p ON p.id = b.access_policy_id
		WHERE (b.asset_id=$1
		    OR `+tagACLSQL("$3")+`)
		  AND (b.expires_at IS NULL OR b.expires_at > $2)
		ORDER BY (b.asset_id IS NULL), b.expires_at NULLS LAST, b.created_at DESC`, in.AssetID, now.UTC(), assetTags)
	if err != nil {
		return AccessResult{}, err
	}
	defer rows.Close()

	roleSet := map[string]struct{}{}
	for _, n := range in.RoleNames {
		roleSet[n] = struct{}{}
	}
	groupSet, err := s.userGroupIDs(ctx, in.UserID)
	if err != nil {
		return AccessResult{}, err
	}

	for rows.Next() {
		var bid uuid.UUID
		var uid, rid, gid, packID, sqlPackID, httpPackID, appPackID, polID *uuid.UUID
		var tStart, tEnd *time.Time
		var expires *time.Time
		var days int
		var roleName *string
		var reqTags, cidrs, countries, devices, namespaces, egress []string
		var requireTicket, requireReason bool
		var maxRisk int
		var riskAction, piiAction string
		var pStart, pEnd *time.Time
		var pDays, pMax int
		var pTags, pCidrs, pCountries, pDevices, pNS, pEgress []string
		var pTicket, pReason bool
		var pCmd, pSQL, pHTTP, pApp *uuid.UUID
		var pAction, pPII string
		var bindAsset *uuid.UUID
		var matchTags []string
		var matchMode string
		if err := rows.Scan(&bid, &uid, &rid, &gid, &tStart, &tEnd, &days, &expires, &reqTags, &requireTicket, &requireReason, &cidrs, &countries, &devices, &namespaces, &egress, &packID, &sqlPackID, &httpPackID, &appPackID, &roleName, &maxRisk, &riskAction, &piiAction, &polID,
			&pStart, &pEnd, &pDays, &pTags, &pTicket, &pReason, &pCidrs, &pCountries, &pDevices, &pNS, &pEgress, &pCmd, &pSQL, &pHTTP, &pApp, &pMax, &pAction, &pPII, &bindAsset, &matchTags, &matchMode); err != nil {
			return AccessResult{}, err
		}
		c := overlayConstraints(aclConstraints{
			TimeStart: tStart, TimeEnd: tEnd, DaysOfWeek: days,
			RequiredTags: reqTags, RequireTicket: requireTicket, RequireReason: requireReason,
			AllowedCIDRs: cidrs, AllowedCountries: countries, AllowedDevices: devices, AllowedNamespaces: namespaces, AllowedEgress: egress,
			CommandPolicyPackID: packID, SQLPolicyPackID: sqlPackID, HTTPPolicyPackID: httpPackID, AppObjectPackID: appPackID,
			MaxRisk: maxRisk, RiskAction: riskAction, PIIAction: piiAction,
		}, aclConstraints{
			TimeStart: pStart, TimeEnd: pEnd, DaysOfWeek: pDays,
			RequiredTags: pTags, RequireTicket: pTicket, RequireReason: pReason,
			AllowedCIDRs: pCidrs, AllowedCountries: pCountries, AllowedDevices: pDevices, AllowedNamespaces: pNS, AllowedEgress: pEgress,
			CommandPolicyPackID: pCmd, SQLPolicyPackID: pSQL, HTTPPolicyPackID: pHTTP, AppObjectPackID: pApp,
			MaxRisk: pMax, RiskAction: pAction, PIIAction: pPII,
		}, polID != nil)
		tStart, tEnd, days = c.TimeStart, c.TimeEnd, c.DaysOfWeek
		reqTags, requireTicket, requireReason = c.RequiredTags, c.RequireTicket, c.RequireReason
		cidrs, countries, devices, namespaces, egress = c.AllowedCIDRs, c.AllowedCountries, c.AllowedDevices, c.AllowedNamespaces, c.AllowedEgress
		packID, sqlPackID, httpPackID, appPackID = c.CommandPolicyPackID, c.SQLPolicyPackID, c.HTTPPolicyPackID, c.AppObjectPackID
		maxRisk, riskAction, piiAction = c.MaxRisk, c.RiskAction, c.PIIAction
		match := matchWHO(in.UserID, uid, rid, gid, roleName, roleSet, groupSet)
		if !match {
			continue
		}
		if !dayAllowed(days, now) {
			continue
		}
		if !timeAllowed(tStart, tEnd, now) {
			continue
		}
		needed := normalizeTags(reqTags)
		if len(needed) > 0 {
			if !hasAll(userTagSet, needed) || !hasAll(assetTagSet, needed) {
				continue
			}
		}
		if requireTicket && !in.IgnoreTicket && ticket == "" {
			continue
		}
		if requireReason && strings.TrimSpace(in.Reason) == "" {
			continue
		}
		if !ipAllowed(cidrs, in.ClientIP) {
			continue
		}
		cc := in.ClientCountry
		if cc == "" {
			cc = s.ClientCountry(in.ClientIP)
		}
		if !geoip.Allowed(geoip.NormalizeCountries(countries), cc) {
			continue
		}
		if !device.Allowed(devices, in.ClientDevices) {
			continue
		}
		idCopy := bid
		res := AccessResult{
			OK: true, BindingID: &idCopy, GroupID: gid, CommandPolicyPackID: packID, SQLPolicyPackID: sqlPackID, HTTPPolicyPackID: httpPackID, AppObjectPackID: appPackID,
			AccessPolicyID:    polID,
			AllowedNamespaces: normalizeNamespaces(namespaces),
			AllowedEgress:     egress,
			MaxRisk:           maxRisk, RiskAction: riskAction, PIIAction: piiAction,
			TagACL: bindAsset == nil, MatchTags: normalizeTags(matchTags), MatchMode: matchMode,
		}
		s.applyRisk(ctx, in, &res, expires)
		if res.OK {
			s.applyOPA(ctx, in, userTags, &res)
		}
		return res, nil
	}
	if err := rows.Err(); err != nil {
		return AccessResult{}, err
	}
	return AccessResult{OK: false}, nil
}

func (s *Service) Allowed(ctx context.Context, in AccessCheck) (bool, error) {
	r, err := s.Evaluate(ctx, in)
	return r.OK, err
}
