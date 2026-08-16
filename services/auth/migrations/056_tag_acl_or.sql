-- +goose Up

-- Tag ACL selector: all (AND, default) or any (OR). Direct asset_id rows keep default 'all' unused.

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS asset_match_mode TEXT NOT NULL DEFAULT 'all';

ALTER TABLE asset_access_bindings
    DROP CONSTRAINT IF EXISTS asset_access_bindings_match_mode_check;

ALTER TABLE asset_access_bindings
    ADD CONSTRAINT asset_access_bindings_match_mode_check
    CHECK (asset_match_mode IN ('all', 'any'));

-- +goose Down

ALTER TABLE asset_access_bindings DROP CONSTRAINT IF EXISTS asset_access_bindings_match_mode_check;
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS asset_match_mode;
