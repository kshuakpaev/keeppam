-- +goose Up

-- Session four-eyes (main22 T-23): supervisor must authorize before connect.

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS require_supervisor BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS supervisor_group_id UUID REFERENCES groups(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_assets_supervisor_group ON assets (supervisor_group_id)
    WHERE supervisor_group_id IS NOT NULL;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS require_supervisor BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS supervisor_group_id UUID REFERENCES groups(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS supervisor_id UUID REFERENCES users(id),
    ADD COLUMN IF NOT EXISTS supervisor_approved_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_sessions_waiting_supervisor
    ON sessions (created_at DESC)
    WHERE require_supervisor AND supervisor_approved_at IS NULL AND status = 'pending';

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-00000000003a', 'sessions.supervise', 'Authorize or deny sessions that require a supervisor (four eyes)')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name = 'sessions.supervise'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000004', id FROM permissions
WHERE name = 'sessions.supervise'
ON CONFLICT DO NOTHING;

-- +goose Down

DELETE FROM role_permissions WHERE permission_id = '01900000-0000-7000-8000-00000000003a';
DELETE FROM permissions WHERE name = 'sessions.supervise';

DROP INDEX IF EXISTS idx_sessions_waiting_supervisor;
ALTER TABLE sessions DROP COLUMN IF EXISTS supervisor_approved_at;
ALTER TABLE sessions DROP COLUMN IF EXISTS supervisor_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS supervisor_group_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS require_supervisor;

DROP INDEX IF EXISTS idx_assets_supervisor_group;
ALTER TABLE assets DROP COLUMN IF EXISTS supervisor_group_id;
ALTER TABLE assets DROP COLUMN IF EXISTS require_supervisor;
