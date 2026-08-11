-- +goose Up

CREATE TABLE app_integrations (
    asset_id         UUID PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    auth_mode        TEXT NOT NULL DEFAULT 'vault_password'
                     CHECK (auth_mode IN ('oidc_broker', 'vault_password', 'header_inject')),
    login_url        TEXT NOT NULL DEFAULT '',
    oidc_issuer      TEXT NOT NULL DEFAULT '',
    oidc_client_id   TEXT NOT NULL DEFAULT '',
    oidc_client_secret_enc BYTEA,
    recording_mode   TEXT NOT NULL DEFAULT 'off'
                     CHECK (recording_mode IN ('off', 'full')),
    header_name      TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE credential_leases (
    id           UUID PRIMARY KEY,
    asset_id     UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    account_id   UUID NOT NULL REFERENCES asset_accounts(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'consumed', 'expired', 'revoked')),
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_credential_leases_user ON credential_leases (user_id, status);
CREATE INDEX idx_credential_leases_exp ON credential_leases (expires_at) WHERE status = 'active';

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-000000000040', 'apps.read', 'View application integrations and leases'),
    ('01900000-0000-7000-8000-000000000041', 'apps.write', 'Manage application integrations')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name IN ('apps.read', 'apps.write')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-000000000040')
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM role_permissions WHERE permission_id IN (
    '01900000-0000-7000-8000-000000000040',
    '01900000-0000-7000-8000-000000000041'
);
DELETE FROM permissions WHERE name IN ('apps.read', 'apps.write');
DROP TABLE IF EXISTS credential_leases;
DROP TABLE IF EXISTS app_integrations;
