-- +goose Up

CREATE TABLE user_vault_ssh_keys (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    public_key   TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    private_enc  BYTEA NOT NULL,
    active       BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   UUID REFERENCES users(id),
    UNIQUE (user_id, fingerprint)
);

CREATE UNIQUE INDEX user_vault_ssh_keys_one_active
    ON user_vault_ssh_keys (user_id) WHERE active;

CREATE INDEX idx_user_vault_ssh_keys_user ON user_vault_ssh_keys (user_id);

ALTER TABLE asset_accounts DROP CONSTRAINT IF EXISTS asset_accounts_auth_method_check;
ALTER TABLE asset_accounts ADD CONSTRAINT asset_accounts_auth_method_check
    CHECK (auth_method IN ('password', 'ssh_key', 'gssapi', 'kubeconfig', 'sa_token', 'user_ssh_key'));

-- +goose Down

UPDATE asset_accounts SET auth_method = 'password' WHERE auth_method = 'user_ssh_key';

ALTER TABLE asset_accounts DROP CONSTRAINT IF EXISTS asset_accounts_auth_method_check;
ALTER TABLE asset_accounts ADD CONSTRAINT asset_accounts_auth_method_check
    CHECK (auth_method IN ('password', 'ssh_key', 'kubeconfig', 'sa_token'));

DROP TABLE IF EXISTS user_vault_ssh_keys;
