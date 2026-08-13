package policy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/geoip"
	"github.com/keeppam/auth/internal/store"
)

type Binding struct {
	ID                    uuid.UUID  `json:"id"`
	AssetID               uuid.UUID  `json:"asset_id"`
	UserID                *uuid.UUID `json:"user_id,omitempty"`
	RoleID                *uuid.UUID `json:"role_id,omitempty"`
	Username              string     `json:"username,omitempty"`
	RoleName              string     `json:"role_name,omitempty"`
	TimeStart             *string    `json:"time_start,omitempty"`
	TimeEnd               *string    `json:"time_end,omitempty"`
	DaysOfWeek            int        `json:"days_of_week"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty"`
	RequiredTags          []string   `json:"required_tags"`
	RequireTicket         bool       `json:"require_ticket"`
	RequireReason         bool       `json:"require_reason"`
	AllowedCIDRs          []string   `json:"allowed_cidrs"`
	AllowedCountries      []string   `json:"allowed_countries"`
	CommandPolicyPackID   *uuid.UUID `json:"command_policy_pack_id,omitempty"`
	CommandPolicyPackName string     `json:"command_policy_pack_name,omitempty"`
	SQLPolicyPackID       *uuid.UUID `json:"sql_policy_pack_id,omitempty"`
	SQLPolicyPackName     string     `json:"sql_policy_pack_name,omitempty"`
	MaxRisk               int        `json:"max_risk"`
	RiskAction            string     `json:"risk_action"`
	CreatedAt             time.Time  `json:"created_at"`
}

type Service struct {
	db  *store.DB
	aud *audit.Service
	geo *geoip.Lookup
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
	CommandPolicyPackID *uuid.UUID `json:"command_policy_pack_id"`
	SQLPolicyPackID     *uuid.UUID `json:"sql_policy_pack_id"`
	MaxRisk             int        `json:"max_risk"`
	RiskAction          string     `json:"risk_action"`
}

type AccessCheck struct {
	UserID        uuid.UUID
	AssetID       uuid.UUID
	RoleNames     []string
	Bypass        bool
	Now           time.Time
	TicketID      string
	Reason        string
	ClientIP      string
	ClientCountry string
	IgnoreTicket  bool
	SkipRisk      bool
}

func (s *Service) ListByAsset(ctx context.Context, assetID uuid.UUID) ([]Binding, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT b.id, b.asset_id, b.user_id, b.role_id,
			COALESCE(u.username,''), COALESCE(r.name,''),
			to_char(b.time_start, 'HH24:MI'), to_char(b.time_end, 'HH24:MI'),
			b.days_of_week, b.expires_at, b.required_tags, b.require_ticket,
			COALESCE(b.require_reason,false), COALESCE(b.allowed_cidrs,'{}'),
			COALESCE(b.allowed_countries,'{}'),
			b.command_policy_pack_id, COALESCE(p.name,''),
			b.sql_policy_pack_id, COALESCE(sp.name,''),
			COALESCE(b.max_risk,0), COALESCE(b.risk_action,'deny'), b.created_at
		FROM asset_access_bindings b
		LEFT JOIN users u ON u.id = b.user_id
		LEFT JOIN roles r ON r.id = b.role_id
		LEFT JOIN command_policy_packs p ON p.id = b.command_policy_pack_id
		LEFT JOIN sql_policy_packs sp ON sp.id = b.sql_policy_pack_id
		WHERE b.asset_id=$1
		ORDER BY b.expires_at NULLS FIRST, COALESCE(u.username, r.name)`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Binding
	for rows.Next() {
		var b Binding
		var ts, te *string
		var tags, cidrs, countries []string
		var packName, sqlPackName string
		if err := rows.Scan(&b.ID, &b.AssetID, &b.UserID, &b.RoleID, &b.Username, &b.RoleName,
			&ts, &te, &b.DaysOfWeek, &b.ExpiresAt, &tags, &b.RequireTicket,
			&b.RequireReason, &cidrs, &countries,
			&b.CommandPolicyPackID, &packName, &b.SQLPolicyPackID, &sqlPackName,
			&b.MaxRisk, &b.RiskAction, &b.CreatedAt); err != nil {
			return nil, err
		}
		b.TimeStart = emptyToNil(ts)
		b.TimeEnd = emptyToNil(te)
		b.RequiredTags = normalizeTags(tags)
		b.AllowedCIDRs = normalizeCIDRs(cidrs)
		b.AllowedCountries = geoip.NormalizeCountries(countries)
		b.CommandPolicyPackName = packName
		b.SQLPolicyPackName = sqlPackName
		out = append(out, b)
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
	seen := map[string]struct{}{}
	var out []string
	for _, t := range in {
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
	if out == nil {
		return []string{}
	}
	return out
}

func (s *Service) Create(ctx context.Context, actorID, assetID uuid.UUID, in CreateBindingInput, ip, ua string) (Binding, error) {
	if (in.UserID == nil && in.RoleID == nil) || (in.UserID != nil && in.RoleID != nil) {
		return Binding{}, fmt.Errorf("specify exactly one of user_id or role_id")
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
	if in.MaxRisk < 0 || in.MaxRisk > 100 {
		return Binding{}, fmt.Errorf("max_risk must be 0..100")
	}
	riskAction := strings.ToLower(strings.TrimSpace(in.RiskAction))
	if riskAction == "" {
		riskAction = "deny"
	}
	if riskAction != "deny" && riskAction != "require_approval" {
		return Binding{}, fmt.Errorf("risk_action must be deny or require_approval")
	}
	id := store.NewID()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO asset_access_bindings
			(id, asset_id, user_id, role_id, time_start, time_end, days_of_week, expires_at, required_tags, require_ticket, require_reason, allowed_cidrs, allowed_countries, command_policy_pack_id, sql_policy_pack_id, max_risk, risk_action, created_at, created_by)
		VALUES ($1,$2,$3,$4,$5::time,$6::time,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,NOW(),$18)`,
		id, assetID, in.UserID, in.RoleID, nullStr(in.TimeStart), nullStr(in.TimeEnd), days, expires, tags, in.RequireTicket, in.RequireReason, cidrs, countries, in.CommandPolicyPackID, in.SQLPolicyPackID, in.MaxRisk, riskAction, actorID)
	if err != nil {
		return Binding{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "asset.acl.granted", "asset", assetID.String(), ip, ua, map[string]any{
		"binding_id": id.String(), "user_id": in.UserID, "role_id": in.RoleID,
		"expires_at": expires, "required_tags": tags, "require_ticket": in.RequireTicket,
		"require_reason": in.RequireReason, "allowed_cidrs": cidrs, "allowed_countries": countries,
		"command_policy_pack_id": in.CommandPolicyPackID, "sql_policy_pack_id": in.SQLPolicyPackID,
		"max_risk": in.MaxRisk, "risk_action": riskAction,
	})
	list, err := s.ListByAsset(ctx, assetID)
	if err != nil {
		return Binding{}, err
	}
	for _, b := range list {
		if b.ID == id {
			return b, nil
		}
	}
	return Binding{ID: id, AssetID: assetID, RequiredTags: tags, RequireTicket: in.RequireTicket}, nil
}

func nullStr(s *string) any {
	if s == nil || *s == "" {
		return nil
	}
	return *s
}

func (s *Service) Delete(ctx context.Context, actorID, bindingID uuid.UUID, ip, ua string) error {
	var assetID uuid.UUID
	err := s.db.Pool.QueryRow(ctx, `DELETE FROM asset_access_bindings WHERE id=$1 RETURNING asset_id`, bindingID).Scan(&assetID)
	if err != nil {
		return err
	}
	return s.aud.Record(ctx, &actorID, "asset.acl.revoked", "asset", assetID.String(), ip, ua, map[string]any{
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
	if out == nil {
		out = []string{}
	}
	return out, rows.Err()
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
		out = append(out, strings.ToLower(t))
	}
	if out == nil {
		out = []string{}
	}
	return out, rows.Err()
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
