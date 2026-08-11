-- +goose Up

CREATE TABLE assets (
    id           UUID PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    asset_type   TEXT NOT NULL DEFAULT 'host'
                 CHECK (asset_type IN ('host', 'db', 'k8s', 'api')),
    hostname     TEXT NOT NULL DEFAULT '',
    address      TEXT NOT NULL,
    port         INT NOT NULL DEFAULT 22,
    protocol     TEXT NOT NULL DEFAULT 'ssh'
                 CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'https', 'postgres', 'mysql')),
    description  TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'disabled')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   UUID REFERENCES users(id)
);

CREATE TABLE asset_tags (
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    tag      TEXT NOT NULL,
    PRIMARY KEY (asset_id, tag)
);

CREATE TABLE asset_accounts (
    id              UUID PRIMARY KEY,
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    username        TEXT NOT NULL,
    auth_method     TEXT NOT NULL DEFAULT 'password'
                    CHECK (auth_method IN ('password', 'ssh_key')),
    secret_enc      BYTEA,
    description     TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID REFERENCES users(id),
    UNIQUE (asset_id, username)
);

CREATE INDEX idx_assets_status ON assets (status);
CREATE INDEX idx_assets_type ON assets (asset_type);
CREATE INDEX idx_asset_tags_tag ON asset_tags (tag);
CREATE INDEX idx_asset_accounts_asset ON asset_accounts (asset_id);

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-000000000016', 'assets.read', 'List and view assets'),
    ('01900000-0000-7000-8000-000000000017', 'assets.write', 'Create and update assets');

-- admin: all new permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name IN ('assets.read', 'assets.write')
ON CONFLICT DO NOTHING;

-- operator: assets.read
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-000000000016')
ON CONFLICT DO NOTHING;

-- auditor: assets.read
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-000000000016')
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM role_permissions WHERE permission_id IN (
    '01900000-0000-7000-8000-000000000016',
    '01900000-0000-7000-8000-000000000017'
);
DELETE FROM permissions WHERE name IN ('assets.read', 'assets.write');
DROP TABLE IF EXISTS asset_accounts;
DROP TABLE IF EXISTS asset_tags;
DROP TABLE IF EXISTS assets;
