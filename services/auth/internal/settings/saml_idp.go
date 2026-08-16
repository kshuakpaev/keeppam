package settings

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/store"
)

const maxExtraSAMLIdPs = 8

type SAMLIdP struct {
	ID              uuid.UUID         `json:"id"`
	Slug            string            `json:"slug"`
	Name            string            `json:"name"`
	Enabled         bool              `json:"enabled"`
	SortOrder       int               `json:"sort_order"`
	MetadataURL     string            `json:"metadata_url"`
	EntityID        string            `json:"entity_id"`
	SSOURL          string            `json:"sso_url"`
	CertPEM         string            `json:"cert_pem"`
	AttrUsername    string            `json:"attr_username"`
	AttrEmail       string            `json:"attr_email"`
	AttrDisplayName string            `json:"attr_display_name"`
	AutoProvision   bool              `json:"auto_provision"`
	SkipMFA         bool              `json:"skip_mfa"`
	DefaultRole     string            `json:"default_role"`
	GroupAttr       string            `json:"group_attr"`
	GroupRoleMap    map[string]string `json:"group_role_map"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	ACSURL          string            `json:"acs_url,omitempty"`
	MetadataSPURL   string            `json:"sp_metadata_url,omitempty"`
	SLOURL          string            `json:"slo_url,omitempty"`
}

type PublicSAMLIdP struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type SAMLIdPInput struct {
	Slug            string            `json:"slug"`
	Name            string            `json:"name"`
	Enabled         *bool             `json:"enabled"`
	MetadataURL     string            `json:"metadata_url"`
	EntityID        string            `json:"entity_id"`
	SSOURL          string            `json:"sso_url"`
	CertPEM         string            `json:"cert_pem"`
	AttrUsername    string            `json:"attr_username"`
	AttrEmail       string            `json:"attr_email"`
	AttrDisplayName string            `json:"attr_display_name"`
	AutoProvision   *bool             `json:"auto_provision"`
	SkipMFA         *bool             `json:"skip_mfa"`
	DefaultRole     string            `json:"default_role"`
	GroupAttr       string            `json:"group_attr"`
	GroupRoleMap    map[string]string `json:"group_role_map"`
}

func NormalizeSAMLSlug(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "default" {
		return "", fmt.Errorf("slug required (not \"default\")")
	}
	if len(s) > 64 {
		return "", fmt.Errorf("slug too long")
	}
	for i, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || (c == '-' && i > 0 && i < len(s)-1)
		if !ok {
			return "", fmt.Errorf("slug must be lowercase alphanumeric with inner dashes")
		}
	}
	return s, nil
}

func IdPConfigured(idp SAMLIdP) bool {
	if strings.TrimSpace(idp.MetadataURL) != "" {
		return true
	}
	return strings.TrimSpace(idp.EntityID) != "" &&
		strings.TrimSpace(idp.SSOURL) != "" &&
		strings.TrimSpace(idp.CertPEM) != ""
}

func IdPFromSettings(cfg AuthSettings) SAMLIdP {
	m := cfg.SAMLGroupRoleMap
	if m == nil {
		m = map[string]string{}
	}
	return SAMLIdP{
		Slug:            "default",
		Name:            "SAML SSO",
		Enabled:         true,
		MetadataURL:     cfg.SAMLIdPMetadataURL,
		EntityID:        cfg.SAMLIdPEntityID,
		SSOURL:          cfg.SAMLIdPSSOURL,
		CertPEM:         cfg.SAMLIdPCertPEM,
		AttrUsername:    cfg.SAMLAttrUsername,
		AttrEmail:       cfg.SAMLAttrEmail,
		AttrDisplayName: cfg.SAMLAttrDisplayName,
		AutoProvision:   cfg.SAMLAutoProvision,
		SkipMFA:         cfg.SAMLSkipMFA,
		DefaultRole:     cfg.SAMLDefaultRole,
		GroupAttr:       cfg.SAMLGroupAttr,
		GroupRoleMap:    m,
	}
}

func (s *Service) OverlaySAML(cfg AuthSettings, idp SAMLIdP) AuthSettings {
	cfg.SAMLIdPMetadataURL = idp.MetadataURL
	cfg.SAMLIdPEntityID = idp.EntityID
	cfg.SAMLIdPSSOURL = idp.SSOURL
	cfg.SAMLIdPCertPEM = idp.CertPEM
	cfg.SAMLAttrUsername = idp.AttrUsername
	cfg.SAMLAttrEmail = idp.AttrEmail
	cfg.SAMLAttrDisplayName = idp.AttrDisplayName
	cfg.SAMLAutoProvision = idp.AutoProvision
	cfg.SAMLSkipMFA = idp.SkipMFA
	cfg.SAMLDefaultRole = idp.DefaultRole
	cfg.SAMLGroupAttr = idp.GroupAttr
	cfg.SAMLGroupRoleMap = idp.GroupRoleMap
	s.fillSAMLDerived(&cfg)
	if idp.Slug != "" && idp.Slug != "default" {
		base := strings.TrimRight(cfg.PublicBaseURL, "/")
		cfg.SAMLACSURL = base + "/api/v1/auth/saml/idp/" + idp.Slug + "/acs"
		cfg.SAMLMetadataURL = base + "/api/v1/auth/saml/idp/" + idp.Slug + "/metadata"
		cfg.SAMLSLOURL = base + "/api/v1/auth/saml/idp/" + idp.Slug + "/slo"
	}
	return cfg
}

func fillIdPDerived(idp *SAMLIdP, publicBase string) {
	base := strings.TrimRight(publicBase, "/")
	if base == "" {
		return
	}
	if idp.Slug == "" || idp.Slug == "default" {
		idp.ACSURL = base + "/api/v1/auth/saml/acs"
		idp.MetadataSPURL = base + "/api/v1/auth/saml/metadata"
		idp.SLOURL = base + "/api/v1/auth/saml/slo"
		return
	}
	idp.ACSURL = base + "/api/v1/auth/saml/idp/" + idp.Slug + "/acs"
	idp.MetadataSPURL = base + "/api/v1/auth/saml/idp/" + idp.Slug + "/metadata"
	idp.SLOURL = base + "/api/v1/auth/saml/idp/" + idp.Slug + "/slo"
}

func (s *Service) ResolveIdP(ctx context.Context, slug string) (SAMLIdP, error) {
	cfg, _, _, err := s.Get(ctx)
	if err != nil {
		return SAMLIdP{}, err
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if slug == "" || slug == "default" {
		idp := IdPFromSettings(cfg)
		fillIdPDerived(&idp, cfg.PublicBaseURL)
		return idp, nil
	}
	idp, err := s.GetIdPBySlug(ctx, slug)
	if err != nil {
		return SAMLIdP{}, err
	}
	fillIdPDerived(&idp, cfg.PublicBaseURL)
	return idp, nil
}

func (s *Service) ListExtraIdPs(ctx context.Context) ([]SAMLIdP, error) {
	cfg, _, _, err := s.Get(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, slug, name, enabled, sort_order, metadata_url, entity_id, sso_url, cert_pem,
		       attr_username, attr_email, attr_display_name, auto_provision, skip_mfa, default_role,
		       group_attr, COALESCE(group_role_map, '{}'::jsonb), created_at, updated_at
		FROM saml_idps WHERE slug <> 'default'
		ORDER BY sort_order, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SAMLIdP
	for rows.Next() {
		idp, err := scanSAMLIdP(rows)
		if err != nil {
			return nil, err
		}
		fillIdPDerived(&idp, cfg.PublicBaseURL)
		out = append(out, idp)
	}
	if out == nil {
		out = []SAMLIdP{}
	}
	return out, rows.Err()
}

func (s *Service) PublicSAMLIdPs(ctx context.Context, cfg AuthSettings) []PublicSAMLIdP {
	if cfg.Mode != "saml" || !cfg.HasSAMLSPKey {
		return []PublicSAMLIdP{}
	}
	out := []PublicSAMLIdP{}
	def := IdPFromSettings(cfg)
	if IdPConfigured(def) {
		out = append(out, PublicSAMLIdP{Slug: "default", Name: def.Name})
	}
	extras, err := s.ListExtraIdPs(ctx)
	if err != nil {
		return out
	}
	for _, idp := range extras {
		if !idp.Enabled || !IdPConfigured(idp) {
			continue
		}
		name := strings.TrimSpace(idp.Name)
		if name == "" {
			name = idp.Slug
		}
		out = append(out, PublicSAMLIdP{Slug: idp.Slug, Name: name})
	}
	return out
}

func (s *Service) GetIdP(ctx context.Context, id uuid.UUID) (SAMLIdP, error) {
	return s.getIdP(ctx, `id=$1`, id)
}

func (s *Service) GetIdPBySlug(ctx context.Context, slug string) (SAMLIdP, error) {
	return s.getIdP(ctx, `slug=$1`, slug)
}

func (s *Service) getIdP(ctx context.Context, where string, arg any) (SAMLIdP, error) {
	row := s.db.Pool.QueryRow(ctx, `
		SELECT id, slug, name, enabled, sort_order, metadata_url, entity_id, sso_url, cert_pem,
		       attr_username, attr_email, attr_display_name, auto_provision, skip_mfa, default_role,
		       group_attr, COALESCE(group_role_map, '{}'::jsonb), created_at, updated_at
		FROM saml_idps WHERE `+where, arg)
	idp, err := scanSAMLIdP(row)
	if err != nil {
		return SAMLIdP{}, err
	}
	cfg, _, _, _ := s.Get(ctx)
	fillIdPDerived(&idp, cfg.PublicBaseURL)
	return idp, nil
}

func (s *Service) CreateIdP(ctx context.Context, actorID uuid.UUID, in SAMLIdPInput, ip, ua string) (SAMLIdP, error) {
	slug, err := NormalizeSAMLSlug(in.Slug)
	if err != nil {
		return SAMLIdP{}, err
	}
	var n int
	if err := s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM saml_idps WHERE slug <> 'default'`).Scan(&n); err != nil {
		return SAMLIdP{}, err
	}
	if n >= maxExtraSAMLIdPs {
		return SAMLIdP{}, fmt.Errorf("at most %d extra SAML IdPs", maxExtraSAMLIdPs)
	}
	idp := applyIdPInput(SAMLIdP{Slug: slug, Enabled: true, AutoProvision: true, SkipMFA: true}, in)
	idp.ID = store.NewID()
	idp.Slug = slug
	now := time.Now().UTC()
	idp.CreatedAt = now
	idp.UpdatedAt = now
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO saml_idps (
			id, slug, name, enabled, sort_order, metadata_url, entity_id, sso_url, cert_pem,
			attr_username, attr_email, attr_display_name, auto_provision, skip_mfa, default_role,
			group_attr, group_role_map, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		idp.ID, idp.Slug, idp.Name, idp.Enabled, n+1, idp.MetadataURL, idp.EntityID, idp.SSOURL, idp.CertPEM,
		idp.AttrUsername, idp.AttrEmail, idp.AttrDisplayName, idp.AutoProvision, idp.SkipMFA, idp.DefaultRole,
		idp.GroupAttr, idp.GroupRoleMap, idp.CreatedAt, idp.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return SAMLIdP{}, fmt.Errorf("slug already exists")
		}
		return SAMLIdP{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "saml.idp.created", "saml_idp", idp.ID.String(), ip, ua, map[string]any{"slug": slug})
	return s.GetIdP(ctx, idp.ID)
}

func (s *Service) UpdateIdP(ctx context.Context, actorID, id uuid.UUID, in SAMLIdPInput, ip, ua string) (SAMLIdP, error) {
	cur, err := s.GetIdP(ctx, id)
	if err != nil {
		return SAMLIdP{}, err
	}
	if cur.Slug == "default" {
		return SAMLIdP{}, fmt.Errorf("edit primary IdP in auth settings")
	}
	idp := applyIdPInput(cur, in)
	idp.UpdatedAt = time.Now().UTC()
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE saml_idps SET
			name=$2, enabled=$3, metadata_url=$4, entity_id=$5, sso_url=$6, cert_pem=$7,
			attr_username=$8, attr_email=$9, attr_display_name=$10, auto_provision=$11, skip_mfa=$12,
			default_role=$13, group_attr=$14, group_role_map=$15, updated_at=$16
		WHERE id=$1`,
		id, idp.Name, idp.Enabled, idp.MetadataURL, idp.EntityID, idp.SSOURL, idp.CertPEM,
		idp.AttrUsername, idp.AttrEmail, idp.AttrDisplayName, idp.AutoProvision, idp.SkipMFA,
		idp.DefaultRole, idp.GroupAttr, idp.GroupRoleMap, idp.UpdatedAt)
	if err != nil {
		return SAMLIdP{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "saml.idp.updated", "saml_idp", id.String(), ip, ua, map[string]any{"slug": cur.Slug})
	return s.GetIdP(ctx, id)
}

func (s *Service) DeleteIdP(ctx context.Context, actorID, id uuid.UUID, ip, ua string) error {
	cur, err := s.GetIdP(ctx, id)
	if err != nil {
		return err
	}
	if cur.Slug == "default" {
		return fmt.Errorf("cannot delete primary IdP")
	}
	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM saml_idps WHERE id=$1 AND slug <> 'default'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return s.aud.Record(ctx, &actorID, "saml.idp.deleted", "saml_idp", id.String(), ip, ua, map[string]any{"slug": cur.Slug})
}

func (s *Service) upsertDefaultIdP(ctx context.Context, cfg AuthSettings) error {
	idp := IdPFromSettings(cfg)
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO saml_idps (
			id, slug, name, enabled, sort_order, metadata_url, entity_id, sso_url, cert_pem,
			attr_username, attr_email, attr_display_name, auto_provision, skip_mfa, default_role,
			group_attr, group_role_map, created_at, updated_at)
		VALUES ($1,'default',$2,TRUE,0,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW(),NOW())
		ON CONFLICT (slug) DO UPDATE SET
			name=EXCLUDED.name, metadata_url=EXCLUDED.metadata_url, entity_id=EXCLUDED.entity_id,
			sso_url=EXCLUDED.sso_url, cert_pem=EXCLUDED.cert_pem, attr_username=EXCLUDED.attr_username,
			attr_email=EXCLUDED.attr_email, attr_display_name=EXCLUDED.attr_display_name,
			auto_provision=EXCLUDED.auto_provision, skip_mfa=EXCLUDED.skip_mfa, default_role=EXCLUDED.default_role,
			group_attr=EXCLUDED.group_attr, group_role_map=EXCLUDED.group_role_map, updated_at=NOW()`,
		store.NewID(), idp.Name, idp.MetadataURL, idp.EntityID, idp.SSOURL, idp.CertPEM,
		idp.AttrUsername, idp.AttrEmail, idp.AttrDisplayName, idp.AutoProvision, idp.SkipMFA, idp.DefaultRole,
		idp.GroupAttr, idp.GroupRoleMap)
	return err
}

func applyIdPInput(cur SAMLIdP, in SAMLIdPInput) SAMLIdP {
	if strings.TrimSpace(in.Name) != "" {
		cur.Name = strings.TrimSpace(in.Name)
	}
	if cur.Name == "" {
		cur.Name = cur.Slug
	}
	if in.Enabled != nil {
		cur.Enabled = *in.Enabled
	}
	cur.MetadataURL = strings.TrimSpace(in.MetadataURL)
	cur.EntityID = strings.TrimSpace(in.EntityID)
	cur.SSOURL = strings.TrimSpace(in.SSOURL)
	cur.CertPEM = strings.TrimSpace(in.CertPEM)
	if strings.TrimSpace(in.AttrUsername) != "" {
		cur.AttrUsername = strings.TrimSpace(in.AttrUsername)
	}
	if cur.AttrUsername == "" {
		cur.AttrUsername = "uid"
	}
	if strings.TrimSpace(in.AttrEmail) != "" {
		cur.AttrEmail = strings.TrimSpace(in.AttrEmail)
	}
	if cur.AttrEmail == "" {
		cur.AttrEmail = "email"
	}
	if strings.TrimSpace(in.AttrDisplayName) != "" {
		cur.AttrDisplayName = strings.TrimSpace(in.AttrDisplayName)
	}
	if cur.AttrDisplayName == "" {
		cur.AttrDisplayName = "displayName"
	}
	if in.AutoProvision != nil {
		cur.AutoProvision = *in.AutoProvision
	}
	if in.SkipMFA != nil {
		cur.SkipMFA = *in.SkipMFA
	}
	if strings.TrimSpace(in.DefaultRole) != "" {
		cur.DefaultRole = strings.TrimSpace(in.DefaultRole)
	}
	if cur.DefaultRole == "" || strings.EqualFold(cur.DefaultRole, "admin") {
		cur.DefaultRole = "operator"
	}
	if strings.TrimSpace(in.GroupAttr) != "" {
		cur.GroupAttr = strings.TrimSpace(in.GroupAttr)
	}
	if cur.GroupAttr == "" {
		cur.GroupAttr = "groups"
	}
	if in.GroupRoleMap != nil {
		cur.GroupRoleMap = in.GroupRoleMap
	}
	if cur.GroupRoleMap == nil {
		cur.GroupRoleMap = map[string]string{}
	}
	return cur
}

type scannable interface {
	Scan(dest ...any) error
}

func scanSAMLIdP(row scannable) (SAMLIdP, error) {
	var idp SAMLIdP
	err := row.Scan(
		&idp.ID, &idp.Slug, &idp.Name, &idp.Enabled, &idp.SortOrder,
		&idp.MetadataURL, &idp.EntityID, &idp.SSOURL, &idp.CertPEM,
		&idp.AttrUsername, &idp.AttrEmail, &idp.AttrDisplayName,
		&idp.AutoProvision, &idp.SkipMFA, &idp.DefaultRole,
		&idp.GroupAttr, &idp.GroupRoleMap, &idp.CreatedAt, &idp.UpdatedAt,
	)
	if idp.GroupRoleMap == nil {
		idp.GroupRoleMap = map[string]string{}
	}
	return idp, err
}
