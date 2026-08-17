package policy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/device"
	"github.com/keeppam/auth/internal/geoip"
	"github.com/keeppam/auth/internal/store"
)

type AccessPolicy struct {
	ID                    uuid.UUID  `json:"id"`
	Name                  string     `json:"name"`
	Description           string     `json:"description"`
	TimeStart             *string    `json:"time_start,omitempty"`
	TimeEnd               *string    `json:"time_end,omitempty"`
	DaysOfWeek            int        `json:"days_of_week"`
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
	MaxRisk               int        `json:"max_risk"`
	RiskAction            string     `json:"risk_action"`
	PIIAction             string       `json:"pii_action"`
	DlpPatterns           []DlpPattern `json:"dlp_patterns"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

type AccessPolicyInput struct {
	Name                string     `json:"name"`
	Description         string     `json:"description"`
	TimeStart           *string    `json:"time_start"`
	TimeEnd             *string    `json:"time_end"`
	DaysOfWeek          *int       `json:"days_of_week"`
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
	MaxRisk             int        `json:"max_risk"`
	RiskAction          string     `json:"risk_action"`
	PIIAction           string       `json:"pii_action"`
	DlpPatterns         []DlpPattern `json:"dlp_patterns"`
}

func (s *Service) ListAccessPolicies(ctx context.Context) ([]AccessPolicy, error) {
	rows, err := s.db.Pool.Query(ctx, accessPolicySelect+" ORDER BY p.name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessPolicy
	for rows.Next() {
		p, err := scanAccessPolicy(rows)
		if err != nil {
			return nil, err
		}
		if err := s.attachDlpPatterns(ctx, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []AccessPolicy{}
	}
	return out, rows.Err()
}

func (s *Service) GetAccessPolicy(ctx context.Context, id uuid.UUID) (AccessPolicy, error) {
	row := s.db.Pool.QueryRow(ctx, accessPolicySelect+" WHERE p.id=$1", id)
	p, err := scanAccessPolicy(row)
	if err != nil {
		return AccessPolicy{}, err
	}
	if err := s.attachDlpPatterns(ctx, &p); err != nil {
		return AccessPolicy{}, err
	}
	return p, nil
}

func (s *Service) CreateAccessPolicy(ctx context.Context, actorID uuid.UUID, in AccessPolicyInput, ip, ua string) (AccessPolicy, error) {
	norm, err := normalizeAccessPolicyInput(in, AccessPolicy{})
	if err != nil {
		return AccessPolicy{}, err
	}
	id := store.NewID()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO access_policies (
			id, name, description, time_start, time_end, days_of_week,
			required_tags, require_ticket, require_reason,
			allowed_cidrs, allowed_countries, allowed_devices, allowed_namespaces, allowed_egress,
			command_policy_pack_id, sql_policy_pack_id, http_policy_pack_id, app_object_pack_id,
			max_risk, risk_action, pii_action, created_at, updated_at, created_by)
		VALUES ($1,$2,$3,$4::time,$5::time,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,NOW(),NOW(),$22)`,
		id, norm.name, norm.description, nullStr(norm.timeStart), nullStr(norm.timeEnd), norm.days,
		norm.tags, norm.requireTicket, norm.requireReason,
		norm.cidrs, norm.countries, norm.devices, norm.namespaces, norm.egress,
		norm.cmdPack, norm.sqlPack, norm.httpPack, norm.appPack,
		norm.maxRisk, norm.riskAction, norm.piiAction, actorID)
	if err != nil {
		return AccessPolicy{}, err
	}
	if err := s.ReplaceDlpPatterns(ctx, id, in.DlpPatterns); err != nil {
		return AccessPolicy{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "access.policy.created", "access_policy", id.String(), ip, ua, map[string]any{
		"name": norm.name, "max_risk": norm.maxRisk,
	})
	return s.GetAccessPolicy(ctx, id)
}

func (s *Service) UpdateAccessPolicy(ctx context.Context, actorID, id uuid.UUID, in AccessPolicyInput, ip, ua string) (AccessPolicy, error) {
	cur, err := s.GetAccessPolicy(ctx, id)
	if err != nil {
		return AccessPolicy{}, err
	}
	if strings.TrimSpace(in.Name) == "" {
		in.Name = cur.Name
	}
	if in.DaysOfWeek == nil {
		d := cur.DaysOfWeek
		in.DaysOfWeek = &d
	}
	if in.TimeStart == nil {
		in.TimeStart = cur.TimeStart
	}
	if in.TimeEnd == nil {
		in.TimeEnd = cur.TimeEnd
	}
	if in.RiskAction == "" {
		in.RiskAction = cur.RiskAction
	}
	norm, err := normalizeAccessPolicyInput(in, cur)
	if err != nil {
		return AccessPolicy{}, err
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE access_policies SET
			name=$2, description=$3, time_start=$4::time, time_end=$5::time, days_of_week=$6,
			required_tags=$7, require_ticket=$8, require_reason=$9,
			allowed_cidrs=$10, allowed_countries=$11, allowed_devices=$12, allowed_namespaces=$13, allowed_egress=$14,
			command_policy_pack_id=$15, sql_policy_pack_id=$16, http_policy_pack_id=$17, app_object_pack_id=$18,
			max_risk=$19, risk_action=$20, pii_action=$21, updated_at=NOW()
		WHERE id=$1`,
		id, norm.name, norm.description, nullStr(norm.timeStart), nullStr(norm.timeEnd), norm.days,
		norm.tags, norm.requireTicket, norm.requireReason,
		norm.cidrs, norm.countries, norm.devices, norm.namespaces, norm.egress,
		norm.cmdPack, norm.sqlPack, norm.httpPack, norm.appPack,
		norm.maxRisk, norm.riskAction, norm.piiAction)
	if err != nil {
		return AccessPolicy{}, err
	}
	if in.DlpPatterns != nil {
		if err := s.ReplaceDlpPatterns(ctx, id, in.DlpPatterns); err != nil {
			return AccessPolicy{}, err
		}
	}
	_ = s.aud.Record(ctx, &actorID, "access.policy.updated", "access_policy", id.String(), ip, ua, map[string]any{
		"name": norm.name,
	})
	return s.GetAccessPolicy(ctx, id)
}

func (s *Service) DeleteAccessPolicy(ctx context.Context, actorID, id uuid.UUID, ip, ua string) error {
	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM access_policies WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return s.aud.Record(ctx, &actorID, "access.policy.deleted", "access_policy", id.String(), ip, ua, nil)
}

const accessPolicySelect = `
		SELECT p.id, p.name, p.description,
			to_char(p.time_start, 'HH24:MI'), to_char(p.time_end, 'HH24:MI'),
			p.days_of_week, p.required_tags, p.require_ticket, p.require_reason,
			COALESCE(p.allowed_cidrs,'{}'), COALESCE(p.allowed_countries,'{}'),
			COALESCE(p.allowed_devices,'{}'), COALESCE(p.allowed_namespaces,'{}'),
			COALESCE(p.allowed_egress,'{}'),
			p.command_policy_pack_id, COALESCE(cp.name,''),
			p.sql_policy_pack_id, COALESCE(sp.name,''),
			p.http_policy_pack_id, COALESCE(hp.name,''),
			p.app_object_pack_id, COALESCE(ao.name,''),
			p.max_risk, p.risk_action, COALESCE(p.pii_action,''), p.created_at, p.updated_at
		FROM access_policies p
		LEFT JOIN command_policy_packs cp ON cp.id = p.command_policy_pack_id
		LEFT JOIN sql_policy_packs sp ON sp.id = p.sql_policy_pack_id
		LEFT JOIN http_policy_packs hp ON hp.id = p.http_policy_pack_id
		LEFT JOIN app_object_packs ao ON ao.id = p.app_object_pack_id`

func scanAccessPolicy(row scannable) (AccessPolicy, error) {
	var p AccessPolicy
	var ts, te *string
	var tags, cidrs, countries, devices, namespaces, egress []string
	var cmdName, sqlName, httpName, appName string
	err := row.Scan(&p.ID, &p.Name, &p.Description, &ts, &te, &p.DaysOfWeek, &tags, &p.RequireTicket, &p.RequireReason,
		&cidrs, &countries, &devices, &namespaces, &egress,
		&p.CommandPolicyPackID, &cmdName, &p.SQLPolicyPackID, &sqlName, &p.HTTPPolicyPackID, &httpName,
		&p.AppObjectPackID, &appName,
		&p.MaxRisk, &p.RiskAction, &p.PIIAction, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return AccessPolicy{}, err
	}
	p.TimeStart = emptyToNil(ts)
	p.TimeEnd = emptyToNil(te)
	p.RequiredTags = normalizeTags(tags)
	p.AllowedCIDRs = normalizeCIDRs(cidrs)
	p.AllowedCountries = geoip.NormalizeCountries(countries)
	p.AllowedDevices = device.Normalize(devices)
	p.AllowedNamespaces = normalizeNamespaces(namespaces)
	p.AllowedEgress = egress
	if p.AllowedEgress == nil {
		p.AllowedEgress = []string{}
	}
	p.CommandPolicyPackName = cmdName
	p.SQLPolicyPackName = sqlName
	p.HTTPPolicyPackName = httpName
	p.AppObjectPackName = appName
	return p, nil
}

type normalizedPolicy struct {
	name, description, riskAction, piiAction            string
	timeStart, timeEnd                                  *string
	days, maxRisk                                       int
	tags, cidrs, countries, devices, namespaces, egress []string
	requireTicket, requireReason                        bool
	cmdPack, sqlPack, httpPack, appPack                 *uuid.UUID
}

func normalizeAccessPolicyInput(in AccessPolicyInput, cur AccessPolicy) (normalizedPolicy, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return normalizedPolicy{}, fmt.Errorf("name required")
	}
	days := 127
	if in.DaysOfWeek != nil {
		days = *in.DaysOfWeek
	} else if cur.ID != uuid.Nil {
		days = cur.DaysOfWeek
	}
	if days < 0 || days > 127 {
		return normalizedPolicy{}, fmt.Errorf("invalid days_of_week")
	}
	if in.MaxRisk < 0 || in.MaxRisk > 100 {
		return normalizedPolicy{}, fmt.Errorf("max_risk must be 0..100")
	}
	riskAction, err := NormalizeRiskAction(in.RiskAction)
	if err != nil {
		return normalizedPolicy{}, err
	}
	cidrs, err := validateCIDRs(in.AllowedCIDRs)
	if err != nil {
		return normalizedPolicy{}, err
	}
	countries, err := geoip.ValidateCountries(in.AllowedCountries)
	if err != nil {
		return normalizedPolicy{}, err
	}
	devices, err := device.Validate(in.AllowedDevices)
	if err != nil {
		return normalizedPolicy{}, err
	}
	namespaces, err := validateNamespaces(in.AllowedNamespaces)
	if err != nil {
		return normalizedPolicy{}, err
	}
	egress, err := ValidateEgress(in.AllowedEgress)
	if err != nil {
		return normalizedPolicy{}, err
	}
	piiAction, err := NormalizePIIAction(in.PIIAction)
	if err != nil {
		return normalizedPolicy{}, err
	}
	return normalizedPolicy{
		name: name, description: strings.TrimSpace(in.Description), riskAction: riskAction, piiAction: piiAction,
		timeStart: in.TimeStart, timeEnd: in.TimeEnd, days: days, maxRisk: in.MaxRisk,
		tags: normalizeTags(in.RequiredTags), cidrs: cidrs, countries: countries,
		devices: devices, namespaces: namespaces, egress: egress,
		requireTicket: in.RequireTicket, requireReason: in.RequireReason,
		cmdPack: in.CommandPolicyPackID, sqlPack: in.SQLPolicyPackID, httpPack: in.HTTPPolicyPackID, appPack: in.AppObjectPackID,
	}, nil
}
