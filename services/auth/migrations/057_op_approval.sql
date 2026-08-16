-- +goose Up

-- In-session HTTP/kubectl object ACL: hold the request until access.approve or timeout.

CREATE TABLE IF NOT EXISTS session_op_approvals (
    id          UUID PRIMARY KEY,
    session_id  UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,
    object_name TEXT NOT NULL,
    pack_name   TEXT NOT NULL DEFAULT '',
    channel     TEXT NOT NULL DEFAULT 'http',
    status      TEXT NOT NULL DEFAULT 'pending',
    approver_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at  TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ NOT NULL,
    CONSTRAINT session_op_approvals_status_check
        CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    CONSTRAINT session_op_approvals_channel_check
        CHECK (channel IN ('http', 'k8s'))
);

CREATE INDEX IF NOT EXISTS idx_op_approvals_pending
    ON session_op_approvals (created_at DESC)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_op_approvals_session
    ON session_op_approvals (session_id, status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_op_approvals_reuse
    ON session_op_approvals (session_id, method, path)
    WHERE status = 'pending';

-- +goose Down

DROP INDEX IF EXISTS idx_op_approvals_reuse;
DROP INDEX IF EXISTS idx_op_approvals_session;
DROP INDEX IF EXISTS idx_op_approvals_pending;
DROP TABLE IF EXISTS session_op_approvals;
