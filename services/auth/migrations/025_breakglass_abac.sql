-- +goose Up

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS allowed_cidrs TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS require_reason BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS break_glass BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS break_glass_events (
    id                UUID PRIMARY KEY,
    asset_id          UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason            TEXT NOT NULL,
    duration_minutes  INT NOT NULL CHECK (duration_minutes > 0 AND duration_minutes <= 60),
    binding_id        UUID REFERENCES asset_access_bindings(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL,
    closed_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS break_glass_events_active_idx
    ON break_glass_events (expires_at)
    WHERE closed_at IS NULL;
CREATE INDEX IF NOT EXISTS break_glass_events_asset_idx
    ON break_glass_events (asset_id, created_at DESC);
CREATE INDEX IF NOT EXISTS break_glass_events_user_idx
    ON break_glass_events (user_id, created_at DESC);

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-00000000002a', 'access.breakglass', 'Emergency break-glass access (loud audit, short TTL)')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name = 'access.breakglass'
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM role_permissions WHERE permission_id = '01900000-0000-7000-8000-00000000002a';
DELETE FROM permissions WHERE name = 'access.breakglass';
DROP TABLE IF EXISTS break_glass_events;
ALTER TABLE sessions DROP COLUMN IF EXISTS break_glass;
ALTER TABLE asset_access_bindings
    DROP COLUMN IF EXISTS allowed_cidrs,
    DROP COLUMN IF EXISTS require_reason;
