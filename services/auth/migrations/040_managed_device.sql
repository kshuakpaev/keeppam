-- +goose Up

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS allowed_devices TEXT[] NOT NULL DEFAULT '{}';

-- +goose Down

ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS allowed_devices;
