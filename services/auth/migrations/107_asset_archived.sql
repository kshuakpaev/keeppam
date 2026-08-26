-- +goose Up
-- Asset archive (status=archived) + allow permanent delete while keeping session history.

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_status_check;
ALTER TABLE assets
    ADD CONSTRAINT assets_status_check
    CHECK (status IN ('active', 'disabled', 'archived'));

ALTER TABLE sessions ALTER COLUMN asset_id DROP NOT NULL;

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_asset_id_fkey;
ALTER TABLE sessions
    ADD CONSTRAINT sessions_asset_id_fkey
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL;

ALTER TABLE session_ad_memberships DROP CONSTRAINT IF EXISTS session_ad_memberships_asset_id_fkey;
ALTER TABLE session_ad_memberships
    ADD CONSTRAINT session_ad_memberships_asset_id_fkey
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE;

ALTER TABLE db_session_roles DROP CONSTRAINT IF EXISTS db_session_roles_asset_id_fkey;
ALTER TABLE db_session_roles
    ADD CONSTRAINT db_session_roles_asset_id_fkey
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE;

-- +goose Down
ALTER TABLE db_session_roles DROP CONSTRAINT IF EXISTS db_session_roles_asset_id_fkey;
ALTER TABLE db_session_roles
    ADD CONSTRAINT db_session_roles_asset_id_fkey
    FOREIGN KEY (asset_id) REFERENCES assets(id);

ALTER TABLE session_ad_memberships DROP CONSTRAINT IF EXISTS session_ad_memberships_asset_id_fkey;
ALTER TABLE session_ad_memberships
    ADD CONSTRAINT session_ad_memberships_asset_id_fkey
    FOREIGN KEY (asset_id) REFERENCES assets(id);

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_asset_id_fkey;
ALTER TABLE sessions
    ADD CONSTRAINT sessions_asset_id_fkey
    FOREIGN KEY (asset_id) REFERENCES assets(id);

UPDATE sessions SET asset_id = (SELECT id FROM assets LIMIT 1) WHERE asset_id IS NULL;
ALTER TABLE sessions ALTER COLUMN asset_id SET NOT NULL;

UPDATE assets SET status = 'disabled' WHERE status = 'archived';
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_status_check;
ALTER TABLE assets
    ADD CONSTRAINT assets_status_check
    CHECK (status IN ('active', 'disabled'));
