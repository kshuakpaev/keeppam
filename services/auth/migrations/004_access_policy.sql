-- +goose Up

CREATE TABLE asset_access_bindings (
    id          UUID PRIMARY KEY,
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id     UUID REFERENCES roles(id) ON DELETE CASCADE,
    time_start  TIME,          -- inclusive, local server time; NULL = any
    time_end    TIME,          -- exclusive; NULL = any
    days_of_week INT NOT NULL DEFAULT 127, -- bitmask Sun=1 .. Sat=64, 127=all
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  UUID REFERENCES users(id),
    CHECK (user_id IS NOT NULL OR role_id IS NOT NULL),
    CHECK (NOT (user_id IS NOT NULL AND role_id IS NOT NULL))
);

CREATE UNIQUE INDEX idx_asset_access_user
    ON asset_access_bindings (asset_id, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX idx_asset_access_role
    ON asset_access_bindings (asset_id, role_id) WHERE role_id IS NOT NULL;
CREATE INDEX idx_asset_access_asset ON asset_access_bindings (asset_id);

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-00000000001a', 'assets.acl', 'Manage asset access bindings')
ON CONFLICT DO NOTHING;

-- admin gets assets.acl
INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name = 'assets.acl'
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM role_permissions WHERE permission_id = '01900000-0000-7000-8000-00000000001a';
DELETE FROM permissions WHERE name = 'assets.acl';
DROP TABLE IF EXISTS asset_access_bindings;
