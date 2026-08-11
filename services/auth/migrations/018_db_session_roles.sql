-- +goose Up

CREATE TABLE db_session_roles (
    session_id   UUID PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    asset_id     UUID NOT NULL REFERENCES assets(id),
    account_id   UUID NOT NULL REFERENCES asset_accounts(id),
    protocol     TEXT NOT NULL CHECK (protocol IN ('postgres', 'mysql')),
    role_name    TEXT NOT NULL,
    privilege    TEXT NOT NULL DEFAULT 'readonly'
                 CHECK (privilege IN ('readonly', 'readwrite')),
    secret_enc   BYTEA NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'dropped', 'failed')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dropped_at   TIMESTAMPTZ,
    last_error   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_db_session_roles_active ON db_session_roles (status)
    WHERE status = 'active';

ALTER TABLE sessions
    ADD COLUMN db_privilege TEXT NOT NULL DEFAULT 'readonly';

-- +goose Down
ALTER TABLE sessions DROP COLUMN IF EXISTS db_privilege;
DROP TABLE IF EXISTS db_session_roles;
