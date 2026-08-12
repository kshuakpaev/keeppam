-- +goose Up

CREATE TABLE user_webauthn_credentials (
    id               UUID PRIMARY KEY,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name             TEXT NOT NULL DEFAULT '',
    credential_id    BYTEA NOT NULL,
    public_key       BYTEA NOT NULL,
    attestation_type TEXT NOT NULL DEFAULT '',
    transport        TEXT[] NOT NULL DEFAULT '{}',
    sign_count       BIGINT NOT NULL DEFAULT 0,
    aaguid           BYTEA NOT NULL DEFAULT ''::bytea,
    backup_eligible  BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (credential_id)
);

CREATE INDEX idx_user_webauthn_user ON user_webauthn_credentials (user_id);

-- +goose Down
DROP TABLE IF EXISTS user_webauthn_credentials;
