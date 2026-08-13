-- +goose Up

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS allowed_countries TEXT[] NOT NULL DEFAULT '{}';

-- +goose Down

ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS allowed_countries;
