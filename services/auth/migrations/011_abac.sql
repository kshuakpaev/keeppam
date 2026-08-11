-- +goose Up

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS required_tags TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS require_ticket BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS user_tags (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tag     TEXT NOT NULL,
    PRIMARY KEY (user_id, tag),
    CHECK (tag <> '')
);

CREATE INDEX IF NOT EXISTS idx_user_tags_tag ON user_tags (tag);

ALTER TABLE access_requests
    ADD COLUMN IF NOT EXISTS ticket_id TEXT NOT NULL DEFAULT '';

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS ticket_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE sessions DROP COLUMN IF EXISTS ticket_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS reason;
ALTER TABLE access_requests DROP COLUMN IF EXISTS ticket_id;
DROP TABLE IF EXISTS user_tags;
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS required_tags;
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS require_ticket;
