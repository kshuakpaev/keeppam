-- +goose Up

ALTER TABLE access_policies
    ADD COLUMN IF NOT EXISTS file_transfer TEXT NOT NULL DEFAULT 'deny'
        CHECK (file_transfer IN ('deny', 'audit', 'capture'));

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS file_transfer TEXT NOT NULL DEFAULT ''
        CHECK (file_transfer IN ('', 'deny', 'audit', 'capture'));

CREATE TABLE IF NOT EXISTS session_files (
    id           UUID PRIMARY KEY,
    session_id   UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    remote_path  TEXT NOT NULL DEFAULT '',
    protocol     TEXT NOT NULL CHECK (protocol IN ('scp', 'sftp')),
    direction    TEXT NOT NULL CHECK (direction IN ('upload', 'download')),
    size_bytes   BIGINT NOT NULL DEFAULT 0,
    sha256       TEXT NOT NULL DEFAULT '',
    stored_path  TEXT NOT NULL DEFAULT '',
    captured     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS session_files_session_idx ON session_files (session_id, created_at);

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-00000000003b', 'sessions.files.read', 'List and download captured SCP/SFTP files')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name = 'sessions.files.read'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-00000000003b'),
    ('01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-00000000003b')
ON CONFLICT DO NOTHING;

-- +goose Down

DELETE FROM role_permissions WHERE permission_id = '01900000-0000-7000-8000-00000000003b';
DELETE FROM permissions WHERE name = 'sessions.files.read';
DROP TABLE IF EXISTS session_files;
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS file_transfer;
ALTER TABLE access_policies DROP COLUMN IF EXISTS file_transfer;
