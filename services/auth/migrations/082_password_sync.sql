-- +goose Up

CREATE TABLE IF NOT EXISTS password_sets (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    sync_order  TEXT NOT NULL DEFAULT 'directory_last'
                CHECK (sync_order IN ('directory_first', 'directory_last')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS password_sets_name_uidx ON password_sets (lower(name));

CREATE TABLE IF NOT EXISTS password_set_members (
    set_id     UUID NOT NULL REFERENCES password_sets(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES asset_accounts(id) ON DELETE CASCADE,
    sort_order INT NOT NULL DEFAULT 0,
    PRIMARY KEY (set_id, account_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS password_set_members_account_uidx
    ON password_set_members (account_id);

CREATE INDEX IF NOT EXISTS password_set_members_set_idx
    ON password_set_members (set_id, sort_order);

-- +goose Down
DROP TABLE IF EXISTS password_set_members;
DROP TABLE IF EXISTS password_sets;
