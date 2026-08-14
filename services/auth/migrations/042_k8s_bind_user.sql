-- +goose Up

ALTER TABLE asset_accounts
    ADD COLUMN IF NOT EXISTS k8s_bind_user BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down

ALTER TABLE asset_accounts DROP COLUMN IF EXISTS k8s_bind_user;
