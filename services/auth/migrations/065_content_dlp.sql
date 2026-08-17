-- +goose Up

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS pii_action TEXT NOT NULL DEFAULT ''
        CHECK (pii_action IN ('', 'mask', 'deny'));

ALTER TABLE access_policies
    ADD COLUMN IF NOT EXISTS pii_action TEXT NOT NULL DEFAULT ''
        CHECK (pii_action IN ('', 'mask', 'deny'));

-- +goose Down

ALTER TABLE access_policies DROP COLUMN IF EXISTS pii_action;
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS pii_action;
