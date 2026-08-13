-- +goose Up

ALTER TABLE asset_accounts
    ADD COLUMN IF NOT EXISTS token_request_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS k8s_sa_namespace TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS k8s_sa_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS token_ttl_seconds INT NOT NULL DEFAULT 900
        CHECK (token_ttl_seconds >= 60 AND token_ttl_seconds <= 86400);

-- +goose Down

ALTER TABLE asset_accounts DROP COLUMN IF EXISTS token_ttl_seconds;
ALTER TABLE asset_accounts DROP COLUMN IF EXISTS k8s_sa_name;
ALTER TABLE asset_accounts DROP COLUMN IF EXISTS k8s_sa_namespace;
ALTER TABLE asset_accounts DROP COLUMN IF EXISTS token_request_enabled;
