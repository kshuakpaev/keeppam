-- +goose Up

-- Tag ACL: WHO + asset tags (AND) instead of one row per asset.
-- Direct asset_id bindings stay more specific and win in Evaluate.

ALTER TABLE asset_access_bindings
    ALTER COLUMN asset_id DROP NOT NULL;

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS asset_match_tags TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE asset_access_bindings
    ADD CONSTRAINT asset_access_bindings_scope_check
    CHECK (
        (asset_id IS NOT NULL AND cardinality(asset_match_tags) = 0)
        OR
        (asset_id IS NULL AND cardinality(asset_match_tags) > 0)
    );

CREATE INDEX IF NOT EXISTS idx_acl_tag_bindings
    ON asset_access_bindings USING GIN (asset_match_tags)
    WHERE asset_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_acl_tag_user
    ON asset_access_bindings (user_id, asset_match_tags)
    WHERE user_id IS NOT NULL AND asset_id IS NULL AND expires_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_acl_tag_role
    ON asset_access_bindings (role_id, asset_match_tags)
    WHERE role_id IS NOT NULL AND asset_id IS NULL AND expires_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_acl_tag_group
    ON asset_access_bindings (group_id, asset_match_tags)
    WHERE group_id IS NOT NULL AND asset_id IS NULL AND expires_at IS NULL;

-- +goose Down

DROP INDEX IF EXISTS idx_acl_tag_group;
DROP INDEX IF EXISTS idx_acl_tag_role;
DROP INDEX IF EXISTS idx_acl_tag_user;
DROP INDEX IF EXISTS idx_acl_tag_bindings;
ALTER TABLE asset_access_bindings DROP CONSTRAINT IF EXISTS asset_access_bindings_scope_check;
DELETE FROM asset_access_bindings WHERE asset_id IS NULL;
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS asset_match_tags;
ALTER TABLE asset_access_bindings ALTER COLUMN asset_id SET NOT NULL;
