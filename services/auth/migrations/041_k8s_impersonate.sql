-- +goose Up

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS allowed_namespaces TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS k8s_namespaces TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE asset_accounts
    ADD COLUMN IF NOT EXISTS k8s_impersonate BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS k8s_impersonate_prefix TEXT NOT NULL DEFAULT 'keeppam:';

-- +goose Down

ALTER TABLE asset_accounts DROP COLUMN IF EXISTS k8s_impersonate_prefix;
ALTER TABLE asset_accounts DROP COLUMN IF EXISTS k8s_impersonate;
ALTER TABLE sessions DROP COLUMN IF EXISTS k8s_namespaces;
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS allowed_namespaces;
