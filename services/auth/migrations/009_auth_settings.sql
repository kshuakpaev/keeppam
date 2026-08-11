-- +goose Up

CREATE TABLE auth_settings (
    id                      INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    mode                    TEXT NOT NULL DEFAULT 'local'
                            CHECK (mode IN ('local', 'oidc', 'ldap')),
    public_base_url         TEXT NOT NULL DEFAULT '',

    oidc_issuer             TEXT NOT NULL DEFAULT '',
    oidc_client_id          TEXT NOT NULL DEFAULT '',
    oidc_client_secret_enc  BYTEA,
    oidc_scopes             TEXT NOT NULL DEFAULT 'openid profile email',
    oidc_auto_provision     BOOLEAN NOT NULL DEFAULT TRUE,
    oidc_skip_mfa           BOOLEAN NOT NULL DEFAULT TRUE,
    oidc_default_role       TEXT NOT NULL DEFAULT 'operator',

    ldap_url                TEXT NOT NULL DEFAULT '',
    ldap_bind_dn            TEXT NOT NULL DEFAULT '',
    ldap_bind_password_enc  BYTEA,
    ldap_user_base_dn       TEXT NOT NULL DEFAULT '',
    ldap_user_filter        TEXT NOT NULL DEFAULT '(uid=%s)',
    ldap_attr_username      TEXT NOT NULL DEFAULT 'uid',
    ldap_attr_email         TEXT NOT NULL DEFAULT 'mail',
    ldap_attr_display_name  TEXT NOT NULL DEFAULT 'cn',
    ldap_start_tls          BOOLEAN NOT NULL DEFAULT FALSE,
    ldap_insecure_tls       BOOLEAN NOT NULL DEFAULT FALSE,
    ldap_auto_provision     BOOLEAN NOT NULL DEFAULT TRUE,
    ldap_skip_mfa           BOOLEAN NOT NULL DEFAULT FALSE,
    ldap_default_role       TEXT NOT NULL DEFAULT 'operator',

    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by              UUID REFERENCES users(id)
);

INSERT INTO auth_settings (id) VALUES (1);

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-00000000001d', 'settings.write', 'Manage system configuration')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name = 'settings.write'
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM role_permissions WHERE permission_id = '01900000-0000-7000-8000-00000000001d';
DELETE FROM permissions WHERE name = 'settings.write';
DROP TABLE IF EXISTS auth_settings;
