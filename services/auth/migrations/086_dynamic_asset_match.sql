-- +goose Up

-- T-20: dynamic WHAT selector beyond tags (name/hostname/type/cidr).
ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS asset_match_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS asset_match_hostname TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS asset_match_types TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS asset_match_cidrs TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE asset_access_bindings DROP CONSTRAINT IF EXISTS asset_access_bindings_scope_check;
ALTER TABLE asset_access_bindings
    ADD CONSTRAINT asset_access_bindings_scope_check
    CHECK (
        (asset_id IS NOT NULL
            AND cardinality(asset_match_tags) = 0
            AND asset_match_name = ''
            AND asset_match_hostname = ''
            AND cardinality(asset_match_types) = 0
            AND cardinality(asset_match_cidrs) = 0)
        OR
        (asset_id IS NULL AND (
            cardinality(asset_match_tags) > 0
            OR asset_match_name <> ''
            OR asset_match_hostname <> ''
            OR cardinality(asset_match_types) > 0
            OR cardinality(asset_match_cidrs) > 0
        ))
    );

-- +goose Down

ALTER TABLE asset_access_bindings DROP CONSTRAINT IF EXISTS asset_access_bindings_scope_check;
ALTER TABLE asset_access_bindings
    ADD CONSTRAINT asset_access_bindings_scope_check
    CHECK (
        (asset_id IS NOT NULL AND cardinality(asset_match_tags) = 0)
        OR
        (asset_id IS NULL AND cardinality(asset_match_tags) > 0)
    );
ALTER TABLE asset_access_bindings
    DROP COLUMN IF EXISTS asset_match_name,
    DROP COLUMN IF EXISTS asset_match_hostname,
    DROP COLUMN IF EXISTS asset_match_types,
    DROP COLUMN IF EXISTS asset_match_cidrs;
