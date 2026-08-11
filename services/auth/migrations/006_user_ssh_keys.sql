-- +goose Up

CREATE TABLE user_ssh_keys (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    public_key   TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   UUID REFERENCES users(id),
    UNIQUE (fingerprint)
);

CREATE INDEX idx_user_ssh_keys_user ON user_ssh_keys (user_id);

-- +goose Down
DROP TABLE IF EXISTS user_ssh_keys;
