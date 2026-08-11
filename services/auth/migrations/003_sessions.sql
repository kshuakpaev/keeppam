-- +goose Up

CREATE TABLE sessions (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id),
    asset_id        UUID NOT NULL REFERENCES assets(id),
    account_id      UUID NOT NULL REFERENCES asset_accounts(id),
    protocol        TEXT NOT NULL DEFAULT 'ssh',
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'active', 'ended', 'failed')),
    client_ip       TEXT NOT NULL DEFAULT '',
    recording_path  TEXT NOT NULL DEFAULT '',
    error_message   TEXT NOT NULL DEFAULT '',
    started_at      TIMESTAMPTZ,
    ended_at        TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE session_events (
    id          UUID PRIMARY KEY,
    session_id  UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type  TEXT NOT NULL,
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_sessions_user ON sessions (user_id, created_at DESC);
CREATE INDEX idx_sessions_asset ON sessions (asset_id, created_at DESC);
CREATE INDEX idx_sessions_status ON sessions (status);
CREATE INDEX idx_session_events_session ON session_events (session_id, ts);

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-000000000018', 'sessions.read', 'List and replay sessions'),
    ('01900000-0000-7000-8000-000000000019', 'sessions.connect', 'Start privileged sessions');

-- admin: both
INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name IN ('sessions.read', 'sessions.connect')
ON CONFLICT DO NOTHING;

-- operator: connect + read (own filtered in API)
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-000000000018'),
    ('01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-000000000019')
ON CONFLICT DO NOTHING;

-- auditor: read only
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-000000000018')
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM role_permissions WHERE permission_id IN (
    '01900000-0000-7000-8000-000000000018',
    '01900000-0000-7000-8000-000000000019'
);
DELETE FROM permissions WHERE name IN ('sessions.read', 'sessions.connect');
DROP TABLE IF EXISTS session_events;
DROP TABLE IF EXISTS sessions;
