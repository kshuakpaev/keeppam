-- +goose Up

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS approval_stages TEXT[] NOT NULL DEFAULT '{manager}';

ALTER TABLE access_requests
    ADD COLUMN IF NOT EXISTS approval_stages TEXT[] NOT NULL DEFAULT '{manager}',
    ADD COLUMN IF NOT EXISTS stage TEXT NOT NULL DEFAULT 'manager';

CREATE TABLE IF NOT EXISTS access_request_approvals (
    id          UUID PRIMARY KEY,
    request_id  UUID NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    stage       TEXT NOT NULL CHECK (stage IN ('manager', 'security')),
    actor_id    UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (request_id, stage)
);

CREATE INDEX IF NOT EXISTS idx_access_request_approvals_req
    ON access_request_approvals (request_id, created_at);

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-00000000001d', 'access.approve.security', 'Second-stage (security) JIT approval')
ON CONFLICT DO NOTHING;

INSERT INTO roles (id, name, description) VALUES
    ('01900000-0000-7000-8000-000000000004', 'security', 'Information security: second-stage JIT approval')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name = 'access.approve.security'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000004', id FROM permissions
WHERE name IN ('access.approve.security', 'access.request', 'assets.read')
ON CONFLICT DO NOTHING;

-- +goose Down

DELETE FROM role_permissions WHERE permission_id = '01900000-0000-7000-8000-00000000001d';
DELETE FROM permissions WHERE name = 'access.approve.security';
DELETE FROM user_role_bindings WHERE role_id = '01900000-0000-7000-8000-000000000004';
DELETE FROM roles WHERE id = '01900000-0000-7000-8000-000000000004';
DROP TABLE IF EXISTS access_request_approvals;
ALTER TABLE access_requests DROP COLUMN IF EXISTS stage;
ALTER TABLE access_requests DROP COLUMN IF EXISTS approval_stages;
ALTER TABLE assets DROP COLUMN IF EXISTS approval_stages;
