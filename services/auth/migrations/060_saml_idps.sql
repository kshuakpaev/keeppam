-- +goose Up

-- Extra SAML IdPs (Entra + Okta + …). Slug `default` mirrors auth_settings (primary IdP).

CREATE TABLE IF NOT EXISTS saml_idps (
    id                UUID PRIMARY KEY,
    slug              TEXT NOT NULL UNIQUE,
    name              TEXT NOT NULL,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order        INT NOT NULL DEFAULT 0,
    metadata_url      TEXT NOT NULL DEFAULT '',
    entity_id         TEXT NOT NULL DEFAULT '',
    sso_url           TEXT NOT NULL DEFAULT '',
    cert_pem          TEXT NOT NULL DEFAULT '',
    attr_username     TEXT NOT NULL DEFAULT 'uid',
    attr_email        TEXT NOT NULL DEFAULT 'email',
    attr_display_name TEXT NOT NULL DEFAULT 'displayName',
    auto_provision    BOOLEAN NOT NULL DEFAULT TRUE,
    skip_mfa          BOOLEAN NOT NULL DEFAULT TRUE,
    default_role      TEXT NOT NULL DEFAULT 'operator',
    group_attr        TEXT NOT NULL DEFAULT 'groups',
    group_role_map    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT saml_idps_slug_chk CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$')
);

INSERT INTO saml_idps (
    id, slug, name, enabled, sort_order,
    metadata_url, entity_id, sso_url, cert_pem,
    attr_username, attr_email, attr_display_name,
    auto_provision, skip_mfa, default_role, group_attr, group_role_map
)
SELECT
    gen_random_uuid(), 'default', 'SAML SSO', TRUE, 0,
    saml_idp_metadata_url, saml_idp_entity_id, saml_idp_sso_url, saml_idp_cert_pem,
    saml_attr_username, saml_attr_email, saml_attr_display_name,
    saml_auto_provision, saml_skip_mfa, saml_default_role,
    COALESCE(saml_group_attr, 'groups'), COALESCE(saml_group_role_map, '{}'::jsonb)
FROM auth_settings WHERE id=1
ON CONFLICT (slug) DO NOTHING;

-- +goose Down

DROP TABLE IF EXISTS saml_idps;
