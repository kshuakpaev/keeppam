-- +goose Up

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS allowed_egress TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE access_policies
    ADD COLUMN IF NOT EXISTS allowed_egress TEXT[] NOT NULL DEFAULT '{}';

-- +goose Down

ALTER TABLE access_policies DROP COLUMN IF EXISTS allowed_egress;
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS allowed_egress;
