-- +goose Up
-- nit2 3.12: protected files with JIT-style access request.

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-0000000000a1', 'files.vault.read', 'List protected files and request access'),
    ('01900000-0000-7000-8000-0000000000a2', 'files.vault.write', 'Upload, delete and approve protected files'),
    ('01900000-0000-7000-8000-0000000000a3', 'sessions.io.read', 'View session I/O stream, transcript and recordings of others')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name IN ('files.vault.read', 'files.vault.write', 'sessions.io.read')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-0000000000a1'),
    ('01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-0000000000a1'),
    ('01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-0000000000a3')
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS protected_files (
    id           UUID PRIMARY KEY,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    sha256       TEXT NOT NULL DEFAULT '',
    size_bytes   BIGINT NOT NULL DEFAULT 0,
    blob_enc     BYTEA NOT NULL,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS protected_files_created_idx ON protected_files (created_at DESC);

CREATE TABLE IF NOT EXISTS protected_file_grants (
    id           UUID PRIMARY KEY,
    file_id      UUID NOT NULL REFERENCES protected_files(id) ON DELETE CASCADE,
    requester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason       TEXT NOT NULL DEFAULT '',
    ttl_minutes  INT NOT NULL DEFAULT 60 CHECK (ttl_minutes > 0 AND ttl_minutes <= 10080),
    status       TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'cancelled', 'expired')),
    approver_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    decided_at   TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS protected_file_grants_file_idx ON protected_file_grants (file_id, created_at DESC);
CREATE INDEX IF NOT EXISTS protected_file_grants_req_idx ON protected_file_grants (requester_id, status);

-- +goose Down
DROP TABLE IF EXISTS protected_file_grants;
DROP TABLE IF EXISTS protected_files;
DELETE FROM role_permissions WHERE permission_id IN (
    '01900000-0000-7000-8000-0000000000a1',
    '01900000-0000-7000-8000-0000000000a2',
    '01900000-0000-7000-8000-0000000000a3'
);
DELETE FROM permissions WHERE id IN (
    '01900000-0000-7000-8000-0000000000a1',
    '01900000-0000-7000-8000-0000000000a2',
    '01900000-0000-7000-8000-0000000000a3'
);
