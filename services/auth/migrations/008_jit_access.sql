-- +goose Up

ALTER TABLE asset_access_bindings ADD COLUMN expires_at TIMESTAMPTZ;

DROP INDEX IF EXISTS idx_asset_access_user;
DROP INDEX IF EXISTS idx_asset_access_role;

-- Permanent bindings remain unique; JIT (with expires_at) can stack.
CREATE UNIQUE INDEX idx_asset_access_user_perm
    ON asset_access_bindings (asset_id, user_id)
    WHERE user_id IS NOT NULL AND expires_at IS NULL;
CREATE UNIQUE INDEX idx_asset_access_role_perm
    ON asset_access_bindings (asset_id, role_id)
    WHERE role_id IS NOT NULL AND expires_at IS NULL;
CREATE INDEX idx_asset_access_expires ON asset_access_bindings (expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE access_requests (
    id               UUID PRIMARY KEY,
    asset_id         UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    requester_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason           TEXT NOT NULL DEFAULT '',
    duration_minutes INT NOT NULL CHECK (duration_minutes > 0 AND duration_minutes <= 1440),
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'approved', 'denied', 'cancelled', 'expired')),
    approver_id      UUID REFERENCES users(id),
    decided_at       TIMESTAMPTZ,
    binding_id       UUID REFERENCES asset_access_bindings(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_access_requests_status ON access_requests (status, created_at DESC);
CREATE INDEX idx_access_requests_requester ON access_requests (requester_id, created_at DESC);
CREATE INDEX idx_access_requests_asset ON access_requests (asset_id, created_at DESC);

-- One open request per user+asset
CREATE UNIQUE INDEX idx_access_requests_pending
    ON access_requests (asset_id, requester_id)
    WHERE status = 'pending';

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-00000000001b', 'access.request', 'Request temporary asset access'),
    ('01900000-0000-7000-8000-00000000001c', 'access.approve', 'Approve or deny access requests')
ON CONFLICT DO NOTHING;

-- admin: approve (+ already has assets.acl)
INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name IN ('access.request', 'access.approve')
ON CONFLICT DO NOTHING;

-- operator: can request
INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000002', id FROM permissions
WHERE name = 'access.request'
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM role_permissions WHERE permission_id IN (
    '01900000-0000-7000-8000-00000000001b',
    '01900000-0000-7000-8000-00000000001c'
);
DELETE FROM permissions WHERE name IN ('access.request', 'access.approve');
DROP TABLE IF EXISTS access_requests;
DROP INDEX IF EXISTS idx_asset_access_expires;
DROP INDEX IF EXISTS idx_asset_access_user_perm;
DROP INDEX IF EXISTS idx_asset_access_role_perm;
CREATE UNIQUE INDEX idx_asset_access_user
    ON asset_access_bindings (asset_id, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX idx_asset_access_role
    ON asset_access_bindings (asset_id, role_id) WHERE role_id IS NOT NULL;
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS expires_at;
