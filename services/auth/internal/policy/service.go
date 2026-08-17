package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/device"
	"github.com/keeppam/auth/internal/geoip"
	"github.com/keeppam/auth/internal/store"
	"github.com/keeppam/auth/internal/tagpath"
)

type Binding struct {
	ID                    uuid.UUID  `json:"id"`
	AssetID               *uuid.UUID `json:"asset_id,omitempty"`
	AssetMatchTags        []string   `json:"asset_match_tags"`
	AssetMatchMode        string     `json:"asset_match_mode,omitempty"`
	Inherited             bool       `json:"inherited"`
	UserID                *uuid.UUID `json:"user_id,omitempty"`
	RoleID                *uuid.UUID `json:"role_id,omitempty"`
	GroupID               *uuid.UUID `json:"group_id,omitempty"`
	Username              string     `json:"username,omitempty"`
	RoleName              string     `json:"role_name,omitempty"`
	GroupName             string     `json:"group_name,omitempty"`
	TimeStart             *string    `json:"time_start,omitempty"`
	TimeEnd               *string    `json:"time_end,omitempty"`
	DaysOfWeek            int        `json:"days_of_week"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty"`
	RequiredTags          []string   `json:"required_tags"`
	RequireTicket         bool       `json:"require_ticket"`
	RequireReason         bool       `json:"require_reason"`
	AllowedCIDRs          []string   `json:"allowed_cidrs"`
	AllowedCountries      []string   `json:"allowed_countries"`
	AllowedDevices        []string   `json:"allowed_devices"`
	AllowedNamespaces     []string   `json:"allowed_namespaces"`
	AllowedEgress         []string   `json:"allowed_egress"`
	CommandPolicyPackID   *uuid.UUID `json:"command_policy_pack_id,omitempty"`
	CommandPolicyPackName string     `json:"command_policy_pack_name,omitempty"`
	SQLPolicyPackID       *uuid.UUID `json:"sql_policy_pack_id,omitempty"`
	SQLPolicyPackName     string     `json:"sql_policy_pack_name,omitempty"`
	HTTPPolicyPackID      *uuid.UUID `json:"http_policy_pack_id,omitempty"`
	HTTPPolicyPackName    string     `json:"http_policy_pack_name,omitempty"`
	AppObjectPackID       *uuid.UUID `json:"app_object_pack_id,omitempty"`
	AppObjectPackName     string     `json:"app_object_pack_name,omitempty"`
	AccessPolicyID        *uuid.UUID `json:"access_policy_id,omitempty"`
	AccessPolicyName      string     `json:"access_policy_name,omitempty"`
	MaxRisk               int        `json:"max_risk"`
	RiskAction            string     `json:"risk_action"`
	PIIAction             string     `json:"pii_action"`
	CreatedAt             time.Time  `json:"created_at"`
}

type Service struct {
	db  *store.DB
	aud *audit.Service
	geo *geoip.Lookup
	opa *Engine
}

func New(db *store.DB, aud *audit.Service) *Service {
	return &Service{db: db, aud: aud, geo: geoip.New("")}
}

func (s *Service) SetGeo(l *geoip.Lookup) {
	if l != nil {
		s.geo = l
	}
}

func (s *Service) Geo() *geoip.Lookup { return s.geo }

func (s *Service) ClientCountry(ip string) string {
	if s.geo == nil {
		return geoip.Classify(ip)
	}
	return s.geo.Country(ip)
}

type CreateBindingInput struct {
	UserID              *uuid.UUID `json:"user_id"`
	RoleID              *uuid.UUID `json:"role_id"`
	GroupID             *uuid.UUID `json:"group_id"`
	TimeStart           *string    `json:"time_start"`
	TimeEnd             *string    `json:"time_end"`
	DaysOfWeek          *int       `json:"days_of_week"`
	ExpiresAt           *time.Time `json:"expires_at"`
	DurationMinutes     *int       `json:"duration_minutes"`
	RequiredTags        []string   `json:"required_tags"`
	RequireTicket       bool       `json:"require_ticket"`
	RequireReason       bool       `json:"require_reason"`
	AllowedCIDRs        []string   `json:"allowed_cidrs"`
	AllowedCountries    []string   `json:"allowed_countries"`
	AllowedDevices      []string   `json:"allowed_devices"`
	AllowedNamespaces   []string   `json:"allowed_namespaces"`
	AllowedEgress       []string   `json:"allowed_egress"`
	CommandPolicyPackID *uuid.UUID `json:"command_policy_pack_id"`
	SQLPolicyPackID     *uuid.UUID `json:"sql_policy_pack_id"`
	HTTPPolicyPackID    *uuid.UUID `json:"http_policy_pack_id"`
	AppObjectPackID     *uuid.UUID `json:"app_object_pack_id"`
	AccessPolicyID      *uuid.UUID `json:"access_policy_id"`
	MaxRisk             int        `json:"max_risk"`
	RiskAction          string     `json:"risk_action"`
	PIIAction           string     `json:"pii_action"`
	AssetMatchTags      []string   `json:"asset_match_tags"`
	AssetMatchMode      string     `json:"asset_match_mode"`
	Permanent           bool       `json:"permanent"`
}

type AccessCheck struct {
	UserID         uuid.UUID
	AssetID        uuid.UUID
	RoleNames      []string
	Bypass         bool
	Now            time.Time
	TicketID       string
	Reason         string
	ClientIP       string
	ClientCountry  string
	ClientDevices  []string
	IgnoreTicket   bool
	SkipRisk       bool
	StepUpVerified bool   // require_mfa already satisfied (connect or in-session grant)
	Operation      string // empty = connect; sql.ddl / k8s.delete / ssh.destructive / http.write / …
	Snapshot       *Snapshot
}

func (s *Service) ListByAsset(ctx context.Context, assetID uuid.UUID) ([]Binding, error) {
	tags, err := s.assetTags(ctx, assetID)
	if err != nil {
		return nil, err
	}
	return s.listBindings(ctx, true, `
		WHERE b.asset_id=$1
		   OR `+tagACLSQL("$2")+`
		ORDER BY (b.asset_id IS NULL), b.expires_at NULLS FIRST, COALESCE(u.username, r.name, g.name)`, assetID, expandTagAncestors(tags))
}

func (s *Service) ListTagBindings(ctx context.Context) ([]Binding, error) {
	return s.listBindings(ctx, true, `
		WHERE b.asset_id IS NULL
		ORDER BY b.created_at DESC`)
}

func (s *Service) getBinding(ctx context.Context, id uuid.UUID) (Binding, error) {
	return s.lookupBinding(ctx, true, id)
}

func (s *Service) GetRaw(ctx context.Context, id uuid.UUID) (Binding, error) {
	return s.lookupBinding(ctx, false, id)
}

func (s *Service) lookupBinding(ctx context.Context, overlay bool, id uuid.UUID) (Binding, error) {
	list, err := s.listBindings(ctx, overlay, `WHERE b.id=$1`, id)
	if err != nil {
		return Binding{}, err
	}
	if len(list) == 0 {
		return Binding{}, pgx.ErrNoRows
	}
	return list[0], nil
}

func (s *Service) listBindings(ctx context.Context, overlay bool, where string, args ...any) ([]Binding, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT b.id, b.asset_id, COALESCE(b.asset_match_tags,'{}'), COALESCE(b.asset_match_mode,'all'), b.user_id, b.role_id, b.group_id,
			COALESCE(u.username,''), COALESCE(r.name,''), COALESCE(g.name,''),
			to_char(b.time_start, 'HH24:MI'), to_char(b.time_end, 'HH24:MI'),
			b.days_of_week, b.expires_at, b.required_tags, b.require_ticket,
			COALESCE(b.require_reason,false), COALESCE(b.allowed_cidrs,'{}'),
			COALESCE(b.allowed_countries,'{}'), COALESCE(b.allowed_devices,'{}'),
			COALESCE(b.allowed_namespaces,'{}'), COALESCE(b.allowed_egress,'{}'),
			b.command_policy_pack_id, COALESCE(p.name,''),
			b.sql_policy_pack_id, COALESCE(sp.name,''),
			b.http_policy_pack_id, COALESCE(hp.name,''),
			b.app_object_pack_id, COALESCE(ao.name,''),
			COALESCE(b.max_risk,0), COALESCE(b.risk_action,'deny'), COALESCE(b.pii_action,''), b.created_at,
			b.access_policy_id, COALESCE(ap.name,''),
			to_char(ap.time_start, 'HH24:MI'), to_char(ap.time_end, 'HH24:MI'),
			COALESCE(ap.days_of_week, 127), COALESCE(ap.required_tags,'{}'),
			COALESCE(ap.require_ticket,false), COALESCE(ap.require_reason,false),
			COALESCE(ap.allowed_cidrs,'{}'), COALESCE(ap.allowed_countries,'{}'),
			COALESCE(ap.allowed_devices,'{}'), COALESCE(ap.allowed_namespaces,'{}'),
			COALESCE(ap.allowed_egress,'{}'),
			ap.command_policy_pack_id, COALESCE(p2.name,''),
			ap.sql_policy_pack_id, COALESCE(sp2.name,''),
			ap.http_policy_pack_id, COALESCE(hp2.name,''),
			ap.app_object_pack_id, COALESCE(ao2.name,''),
			COALESCE(ap.max_risk,0), COALESCE(ap.risk_action,'deny'), COALESCE(ap.pii_action,'')
		FROM asset_access_bindings b
		LEFT JOIN users u ON u.id = b.user_id
		LEFT JOIN roles r ON r.id = b.role_id
		LEFT JOIN groups g ON g.id = b.group_id
		LEFT JOIN command_policy_packs p ON p.id = b.command_policy_pack_id
		LEFT JOIN sql_policy_packs sp ON sp.id = b.sql_policy_pack_id
		LEFT JOIN http_policy_packs hp ON hp.id = b.http_policy_pack_id
		LEFT JOIN app_object_packs ao ON ao.id = b.app_object_pack_id
		LEFT JOIN access_policies ap ON ap.id = b.access_policy_id
		LEFT JOIN command_policy_packs p2 ON p2.id = ap.command_policy_pack_id
		LEFT JOIN sql_policy_packs sp2 ON sp2.id = ap.sql_policy_pack_id
		LEFT JOIN http_policy_packs hp2 ON hp2.id = ap.http_policy_pack_id
		LEFT JOIN app_object_packs ao2 ON ao2.id = ap.app_object_pack_id
		`+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Binding
	for rows.Next() {
		var b Binding
		var ts, te *string
		var tags, cidrs, countries, devices, namespaces, egress []string
		var packName, sqlPackName, httpPackName, appPackName string
		var pts, pte *string
		var pDays, pMax int
		var pTags, pCidrs, pCountries, pDevices, pNS, pEgress []string
		var pTicket, pReason bool
		var pCmd, pSQL, pHTTP, pApp *uuid.UUID
		var pCmdName, pSQLName, pHTTPName, pAppName, pAction, pPII string
		if err := rows.Scan(&b.ID, &b.AssetID, &b.AssetMatchTags, &b.AssetMatchMode, &b.UserID, &b.RoleID, &b.GroupID, &b.Username, &b.RoleName, &b.GroupName,
			&ts, &te, &b.DaysOfWeek, &b.ExpiresAt, &tags, &b.RequireTicket,
			&b.RequireReason, &cidrs, &countries, &devices, &namespaces, &egress,
			&b.CommandPolicyPackID, &packName, &b.SQLPolicyPackID, &sqlPackName,
			&b.HTTPPolicyPackID, &httpPackName, &b.AppObjectPackID, &appPackName,
			&b.MaxRisk, &b.RiskAction, &b.PIIAction, &b.CreatedAt,
			&b.AccessPolicyID, &b.AccessPolicyName,
			&pts, &pte, &pDays, &pTags, &pTicket, &pReason,
			&pCidrs, &pCountries, &pDevices, &pNS, &pEgress,
			&pCmd, &pCmdName, &pSQL, &pSQLName, &pHTTP, &pHTTPName, &pApp, &pAppName,
			&pMax, &pAction, &pPII); err != nil {
			return nil, err
		}
		b.TimeStart = emptyToNil(ts)
		b.TimeEnd = emptyToNil(te)
		b.AssetMatchTags = normalizeTags(b.AssetMatchTags)
		if b.AssetMatchMode == "" {
			b.AssetMatchMode = "all"
		}
		b.Inherited = b.AssetID == nil
		b.RequiredTags = normalizeTags(tags)
		b.AllowedCIDRs = normalizeCIDRs(cidrs)
		b.AllowedCountries = geoip.NormalizeCountries(countries)
		b.AllowedDevices = device.Normalize(devices)
		b.AllowedNamespaces = normalizeNamespaces(namespaces)
		b.AllowedEgress = egress
		if b.AllowedEgress == nil {
			b.AllowedEgress = []string{}
		}
		b.CommandPolicyPackName = packName
		b.SQLPolicyPackName = sqlPackName
		b.HTTPPolicyPackName = httpPackName
		b.AppObjectPackName = appPackName
		if overlay && b.AccessPolicyID != nil {
			origCmd, origSQL, origHTTP, origApp := b.CommandPolicyPackID, b.SQLPolicyPackID, b.HTTPPolicyPackID, b.AppObjectPackID
			b.TimeStart = inheritStr(b.TimeStart, emptyToNil(pts))
			b.TimeEnd = inheritStr(b.TimeEnd, emptyToNil(pte))
			if b.DaysOfWeek == 127 {
				b.DaysOfWeek = pDays
			}
			if len(b.RequiredTags) == 0 {
				b.RequiredTags = normalizeTags(pTags)
			}
			b.RequireTicket = b.RequireTicket || pTicket
			b.RequireReason = b.RequireReason || pReason
			if len(b.AllowedCIDRs) == 0 {
				b.AllowedCIDRs = normalizeCIDRs(pCidrs)
			}
			if len(b.AllowedCountries) == 0 {
				b.AllowedCountries = geoip.NormalizeCountries(pCountries)
			}
			if len(b.AllowedDevices) == 0 {
				b.AllowedDevices = device.Normalize(pDevices)
			}
			if len(b.AllowedNamespaces) == 0 {
				b.AllowedNamespaces = normalizeNamespaces(pNS)
			}
			if len(b.AllowedEgress) == 0 {
				b.AllowedEgress = pEgress
				if b.AllowedEgress == nil {
					b.AllowedEgress = []string{}
				}
			}
			if b.CommandPolicyPackID == nil {
				b.CommandPolicyPackID = pCmd
			}
			if b.SQLPolicyPackID == nil {
				b.SQLPolicyPackID = pSQL
			}
			if b.HTTPPolicyPackID == nil {
				b.HTTPPolicyPackID = pHTTP
			}
			if b.AppObjectPackID == nil {
				b.AppObjectPackID = pApp
			}
			if b.MaxRisk == 0 {
				b.MaxRisk = pMax
				if pAction != "" {
					b.RiskAction = pAction
				}
			}
			if origCmd == nil {
				b.CommandPolicyPackName = pCmdName
			}
			if origSQL == nil {
				b.SQLPolicyPackName = pSQLName
			}
			if origHTTP == nil {
				b.HTTPPolicyPackName = pHTTPName
			}
			if origApp == nil {
				b.AppObjectPackName = pAppName
			}
			if b.PIIAction == "" {
				b.PIIAction = pPII
			}
		}
		out = append(out, b)
	}
	if out == nil {
		out = []Binding{}
	}
	return out, rows.Err()
}

func emptyToNil(s *string) *string {
	if s == nil || *s == "" {
		return nil
	}
	return s
}

func normalizeTags(in []string) []string {
	return tagpath.Normalize(in)
}

func normalizeNamespaces(in []string) []string {
	return normalizeTags(in)
}

func validateNamespaces(in []string) ([]string, error) {
	out := normalizeNamespaces(in)
	for _, n := range out {
		if len(n) < 1 || len(n) > 63 || n[0] == '-' || n[len(n)-1] == '-' {
			return nil, fmt.Errorf("invalid namespace %q", n)
		}
		for _, r := range n {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return nil, fmt.Errorf("invalid namespace %q", n)
		}
	}
	return out, nil
}

func (s *Service) Create(ctx context.Context, actorID, assetID uuid.UUID, in CreateBindingInput, ip, ua string) (Binding, error) {
	n := 0
	if in.UserID != nil {
		n++
	}
	if in.RoleID != nil {
		n++
	}
	if in.GroupID != nil {
		n++
	}
	if n != 1 {
		return Binding{}, fmt.Errorf("specify exactly one of user_id, role_id or group_id")
	}
	if in.GroupID != nil {
		var exists bool
		if err := s.db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM groups WHERE id=$1)`, *in.GroupID).Scan(&exists); err != nil || !exists {
			return Binding{}, fmt.Errorf("unknown group_id")
		}
	}
	days := 127
	if in.DaysOfWeek != nil {
		days = *in.DaysOfWeek
		if days < 0 || days > 127 {
			return Binding{}, fmt.Errorf("invalid days_of_week")
		}
	}
	var expires any
	if in.ExpiresAt != nil {
		expires = in.ExpiresAt.UTC()
	} else if in.DurationMinutes != nil {
		m := *in.DurationMinutes
		if m <= 0 || m > 1440 {
			return Binding{}, fmt.Errorf("duration_minutes must be 1..1440")
		}
		expires = time.Now().UTC().Add(time.Duration(m) * time.Minute)
	}
	tags := normalizeTags(in.RequiredTags)
	cidrs, err := validateCIDRs(in.AllowedCIDRs)
	if err != nil {
		return Binding{}, err
	}
	countries, err := geoip.ValidateCountries(in.AllowedCountries)
	if err != nil {
		return Binding{}, err
	}
	devices, err := device.Validate(in.AllowedDevices)
	if err != nil {
		return Binding{}, err
	}
	namespaces, err := validateNamespaces(in.AllowedNamespaces)
	if err != nil {
		return Binding{}, err
	}
	egress, err := ValidateEgress(in.AllowedEgress)
	if err != nil {
		return Binding{}, err
	}
	if in.MaxRisk < 0 || in.MaxRisk > 100 {
		return Binding{}, fmt.Errorf("max_risk must be 0..100")
	}
	riskAction, err := NormalizeRiskAction(in.RiskAction)
	if err != nil {
		return Binding{}, err
	}
	piiAction, err := NormalizePIIAction(in.PIIAction)
	if err != nil {
		return Binding{}, err
	}
	if in.AccessPolicyID != nil {
		if _, err := s.GetAccessPolicy(ctx, *in.AccessPolicyID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return Binding{}, fmt.Errorf("unknown access_policy_id")
			}
			return Binding{}, err
		}
	}
	id := store.NewID()
	matchTags := []string{}
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO asset_access_bindings
			(id, asset_id, asset_match_tags, user_id, role_id, group_id, time_start, time_end, days_of_week, expires_at, required_tags, require_ticket, require_reason, allowed_cidrs, allowed_countries, allowed_devices, allowed_namespaces, allowed_egress, command_policy_pack_id, sql_policy_pack_id, http_policy_pack_id, app_object_pack_id, max_risk, risk_action, pii_action, access_policy_id, created_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7::time,$8::time,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,NOW(),$27)`,
		id, assetID, matchTags, in.UserID, in.RoleID, in.GroupID, nullStr(in.TimeStart), nullStr(in.TimeEnd), days, expires, tags, in.RequireTicket, in.RequireReason, cidrs, countries, devices, namespaces, egress, in.CommandPolicyPackID, in.SQLPolicyPackID, in.HTTPPolicyPackID, in.AppObjectPackID, in.MaxRisk, riskAction, piiAction, in.AccessPolicyID, actorID)
	if err != nil {
		return Binding{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "asset.acl.granted", "asset", assetID.String(), ip, ua, map[string]any{
		"binding_id": id.String(), "user_id": in.UserID, "role_id": in.RoleID, "group_id": in.GroupID,
		"expires_at": expires, "required_tags": tags, "require_ticket": in.RequireTicket,
		"require_reason": in.RequireReason, "allowed_cidrs": cidrs, "allowed_countries": countries, "allowed_devices": devices,
		"allowed_namespaces":     namespaces,
		"allowed_egress":         egress,
		"command_policy_pack_id": in.CommandPolicyPackID, "sql_policy_pack_id": in.SQLPolicyPackID,
		"http_policy_pack_id": in.HTTPPolicyPackID,
		"app_object_pack_id":  in.AppObjectPackID,
		"access_policy_id":    in.AccessPolicyID,
		"max_risk":            in.MaxRisk, "risk_action": riskAction,
		"pii_action": piiAction,
	})
	return s.getBinding(ctx, id)
}

func (s *Service) CreateTag(ctx context.Context, actorID uuid.UUID, in CreateBindingInput, ip, ua string) (Binding, error) {
	matchTags := normalizeTags(in.AssetMatchTags)
	if len(matchTags) == 0 {
		return Binding{}, fmt.Errorf("asset_match_tags required")
	}
	in.AssetMatchTags = matchTags
	n := 0
	if in.UserID != nil {
		n++
	}
	if in.RoleID != nil {
		n++
	}
	if in.GroupID != nil {
		n++
	}
	if n != 1 {
		return Binding{}, fmt.Errorf("specify exactly one of user_id, role_id or group_id")
	}
	if in.GroupID != nil {
		var exists bool
		if err := s.db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM groups WHERE id=$1)`, *in.GroupID).Scan(&exists); err != nil || !exists {
			return Binding{}, fmt.Errorf("unknown group_id")
		}
	}
	days := 127
	if in.DaysOfWeek != nil {
		days = *in.DaysOfWeek
		if days < 0 || days > 127 {
			return Binding{}, fmt.Errorf("invalid days_of_week")
		}
	}
	var expires any
	if in.ExpiresAt != nil {
		expires = in.ExpiresAt.UTC()
	} else if in.DurationMinutes != nil {
		m := *in.DurationMinutes
		if m <= 0 || m > 1440 {
			return Binding{}, fmt.Errorf("duration_minutes must be 1..1440")
		}
		expires = time.Now().UTC().Add(time.Duration(m) * time.Minute)
	}
	tags := normalizeTags(in.RequiredTags)
	cidrs, err := validateCIDRs(in.AllowedCIDRs)
	if err != nil {
		return Binding{}, err
	}
	countries, err := geoip.ValidateCountries(in.AllowedCountries)
	if err != nil {
		return Binding{}, err
	}
	devices, err := device.Validate(in.AllowedDevices)
	if err != nil {
		return Binding{}, err
	}
	namespaces, err := validateNamespaces(in.AllowedNamespaces)
	if err != nil {
		return Binding{}, err
	}
	egress, err := ValidateEgress(in.AllowedEgress)
	if err != nil {
		return Binding{}, err
	}
	if in.MaxRisk < 0 || in.MaxRisk > 100 {
		return Binding{}, fmt.Errorf("max_risk must be 0..100")
	}
	riskAction, err := NormalizeRiskAction(in.RiskAction)
	if err != nil {
		return Binding{}, err
	}
	piiAction, err := NormalizePIIAction(in.PIIAction)
	if err != nil {
		return Binding{}, err
	}
	if in.AccessPolicyID != nil {
		if _, err := s.GetAccessPolicy(ctx, *in.AccessPolicyID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return Binding{}, fmt.Errorf("unknown access_policy_id")
			}
			return Binding{}, err
		}
	}
	id := store.NewID()
	matchMode, err := normalizeMatchMode(in.AssetMatchMode)
	if err != nil {
		return Binding{}, err
	}
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO asset_access_bindings
			(id, asset_id, asset_match_tags, asset_match_mode, user_id, role_id, group_id, time_start, time_end, days_of_week, expires_at, required_tags, require_ticket, require_reason, allowed_cidrs, allowed_countries, allowed_devices, allowed_namespaces, allowed_egress, command_policy_pack_id, sql_policy_pack_id, http_policy_pack_id, app_object_pack_id, max_risk, risk_action, pii_action, access_policy_id, created_at, created_by)
		VALUES ($1,NULL,$2,$3,$4,$5,$6,$7::time,$8::time,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,NOW(),$27)`,
		id, matchTags, matchMode, in.UserID, in.RoleID, in.GroupID, nullStr(in.TimeStart), nullStr(in.TimeEnd), days, expires, tags, in.RequireTicket, in.RequireReason, cidrs, countries, devices, namespaces, egress, in.CommandPolicyPackID, in.SQLPolicyPackID, in.HTTPPolicyPackID, in.AppObjectPackID, in.MaxRisk, riskAction, piiAction, in.AccessPolicyID, actorID)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return Binding{}, fmt.Errorf("tag ACL already exists for this subject")
		}
		return Binding{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "asset.acl.granted", "asset_tags", strings.Join(matchTags, ","), ip, ua, map[string]any{
		"binding_id": id.String(), "user_id": in.UserID, "role_id": in.RoleID, "group_id": in.GroupID,
		"asset_match_tags": matchTags, "asset_match_mode": matchMode, "access_policy_id": in.AccessPolicyID,
		"max_risk": in.MaxRisk, "risk_action": riskAction,
	})
	return s.getBinding(ctx, id)
}

func (s *Service) Update(ctx context.Context, actorID, bindingID uuid.UUID, in CreateBindingInput, ip, ua string) (Binding, error) {
	cur, err := s.GetRaw(ctx, bindingID)
	if err != nil {
		return Binding{}, err
	}
	if in.Permanent && in.DurationMinutes != nil {
		return Binding{}, fmt.Errorf("cannot set both permanent and duration_minutes")
	}
	days := cur.DaysOfWeek
	if in.DaysOfWeek != nil {
		days = *in.DaysOfWeek
		if days < 0 || days > 127 {
			return Binding{}, fmt.Errorf("invalid days_of_week")
		}
	}
	var expires any
	if cur.ExpiresAt != nil {
		expires = cur.ExpiresAt.UTC()
	}
	if in.Permanent {
		expires = nil
	} else if in.DurationMinutes != nil {
		m := *in.DurationMinutes
		if m <= 0 || m > 1440 {
			return Binding{}, fmt.Errorf("duration_minutes must be 1..1440")
		}
		expires = time.Now().UTC().Add(time.Duration(m) * time.Minute)
	}
	tags := normalizeTags(in.RequiredTags)
	cidrs, err := validateCIDRs(in.AllowedCIDRs)
	if err != nil {
		return Binding{}, err
	}
	countries, err := geoip.ValidateCountries(in.AllowedCountries)
	if err != nil {
		return Binding{}, err
	}
	devices, err := device.Validate(in.AllowedDevices)
	if err != nil {
		return Binding{}, err
	}
	namespaces, err := validateNamespaces(in.AllowedNamespaces)
	if err != nil {
		return Binding{}, err
	}
	egress, err := ValidateEgress(in.AllowedEgress)
	if err != nil {
		return Binding{}, err
	}
	if in.MaxRisk < 0 || in.MaxRisk > 100 {
		return Binding{}, fmt.Errorf("max_risk must be 0..100")
	}
	riskAction, err := NormalizeRiskAction(in.RiskAction)
	if err != nil {
		return Binding{}, err
	}
	piiAction, err := NormalizePIIAction(in.PIIAction)
	if err != nil {
		return Binding{}, err
	}
	if in.AccessPolicyID != nil {
		if _, err := s.GetAccessPolicy(ctx, *in.AccessPolicyID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return Binding{}, fmt.Errorf("unknown access_policy_id")
			}
			return Binding{}, err
		}
	}
	matchTags := []string{}
	matchMode := "all"
	if cur.AssetID == nil {
		matchTags = normalizeTags(cur.AssetMatchTags)
		if in.AssetMatchTags != nil {
			matchTags = normalizeTags(in.AssetMatchTags)
		}
		if len(matchTags) == 0 {
			return Binding{}, fmt.Errorf("asset_match_tags required")
		}
		src := in.AssetMatchMode
		if strings.TrimSpace(src) == "" {
			src = cur.AssetMatchMode
		}
		matchMode, err = normalizeMatchMode(src)
		if err != nil {
			return Binding{}, err
		}
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE asset_access_bindings SET
			asset_match_tags=$2, asset_match_mode=$3,
			time_start=$4::time, time_end=$5::time, days_of_week=$6, expires_at=$7,
			required_tags=$8, require_ticket=$9, require_reason=$10,
			allowed_cidrs=$11, allowed_countries=$12, allowed_devices=$13, allowed_namespaces=$14, allowed_egress=$15,
			command_policy_pack_id=$16, sql_policy_pack_id=$17, http_policy_pack_id=$18, app_object_pack_id=$19,
			max_risk=$20, risk_action=$21, pii_action=$22, access_policy_id=$23
		WHERE id=$1`,
		bindingID, matchTags, matchMode, nullStr(in.TimeStart), nullStr(in.TimeEnd), days, expires,
		tags, in.RequireTicket, in.RequireReason, cidrs, countries, devices, namespaces, egress,
		in.CommandPolicyPackID, in.SQLPolicyPackID, in.HTTPPolicyPackID, in.AppObjectPackID,
		in.MaxRisk, riskAction, piiAction, in.AccessPolicyID)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return Binding{}, fmt.Errorf("tag ACL already exists for this subject")
		}
		return Binding{}, err
	}
	resType, resID := "asset", ""
	if cur.AssetID != nil {
		resID = cur.AssetID.String()
	} else {
		resType, resID = "asset_tags", strings.Join(matchTags, ",")
	}
	_ = s.aud.Record(ctx, &actorID, "asset.acl.updated", resType, resID, ip, ua, map[string]any{
		"binding_id":             bindingID.String(),
		"expires_at":             expires,
		"required_tags":          tags,
		"require_ticket":         in.RequireTicket,
		"require_reason":         in.RequireReason,
		"allowed_cidrs":          cidrs,
		"allowed_countries":      countries,
		"allowed_devices":        devices,
		"allowed_namespaces":     namespaces,
		"allowed_egress":         egress,
		"command_policy_pack_id": in.CommandPolicyPackID,
		"sql_policy_pack_id":     in.SQLPolicyPackID,
		"http_policy_pack_id":    in.HTTPPolicyPackID,
		"app_object_pack_id":     in.AppObjectPackID,
		"access_policy_id":       in.AccessPolicyID,
		"asset_match_tags":       matchTags,
		"asset_match_mode":       matchMode,
		"max_risk":               in.MaxRisk,
		"risk_action":            riskAction,
		"pii_action":             piiAction,
	})
	return s.getBinding(ctx, bindingID)
}

func nullStr(s *string) any {
	if s == nil || *s == "" {
		return nil
	}
	return *s
}

func (s *Service) Delete(ctx context.Context, actorID, bindingID uuid.UUID, ip, ua string) error {
	var assetID *uuid.UUID
	var matchTags []string
	err := s.db.Pool.QueryRow(ctx, `
		DELETE FROM asset_access_bindings WHERE id=$1
		RETURNING asset_id, COALESCE(asset_match_tags,'{}')`, bindingID).Scan(&assetID, &matchTags)
	if err != nil {
		return err
	}
	resType, resID := "asset", ""
	if assetID != nil {
		resID = assetID.String()
	} else {
		resType, resID = "asset_tags", strings.Join(normalizeTags(matchTags), ",")
	}
	return s.aud.Record(ctx, &actorID, "asset.acl.revoked", resType, resID, ip, ua, map[string]any{
		"binding_id": bindingID.String(),
	})
}

func (s *Service) UserTags(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := s.db.Pool.Query(ctx, `SELECT tag FROM user_tags WHERE user_id=$1 ORDER BY tag`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return normalizeTags(out), rows.Err()
}

func (s *Service) SetUserTags(ctx context.Context, actorID, userID uuid.UUID, tags []string, ip, ua string) ([]string, error) {
	tags = normalizeTags(tags)
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM user_tags WHERE user_id=$1`, userID); err != nil {
		return nil, err
	}
	for _, t := range tags {
		if _, err := tx.Exec(ctx, `INSERT INTO user_tags (user_id, tag) VALUES ($1,$2)`, userID, t); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	_ = s.aud.Record(ctx, &actorID, "user.tags.updated", "user", userID.String(), ip, ua, map[string]any{"tags": tags})
	return tags, nil
}

func (s *Service) AssetTags(ctx context.Context, assetID uuid.UUID) ([]string, error) {
	return s.assetTags(ctx, assetID)
}

func (s *Service) assetTags(ctx context.Context, assetID uuid.UUID) ([]string, error) {
	rows, err := s.db.Pool.Query(ctx, `SELECT tag FROM asset_tags WHERE asset_id=$1 ORDER BY tag`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return normalizeTags(out), rows.Err()
}

func toSet(tags []string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, t := range tags {
		m[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}
	return m
}

func hasAll(have map[string]struct{}, need []string) bool {
	for _, t := range need {
		if _, ok := have[t]; !ok {
			return false
		}
	}
	return true
}

func dayAllowed(mask int, now time.Time) bool {
	if mask == 0 {
		return false
	}
	bit := 1 << int(now.Weekday())
	return mask&bit != 0
}

func timeAllowed(start, end *time.Time, now time.Time) bool {
	if start == nil && end == nil {
		return true
	}
	mins := now.Hour()*60 + now.Minute()
	s := 0
	e := 24 * 60
	if start != nil {
		s = start.Hour()*60 + start.Minute()
	}
	if end != nil {
		e = end.Hour()*60 + end.Minute()
	}
	if s == e {
		return true
	}
	if s < e {
		return mins >= s && mins < e
	}
	return mins >= s || mins < e
}

func IsNotFound(err error) bool { return err == pgx.ErrNoRows }
