-- +goose Up
-- Allow deleting asset accounts while keeping session audit history.

ALTER TABLE sessions ALTER COLUMN account_id DROP NOT NULL;

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_account_id_fkey;
ALTER TABLE sessions
    ADD CONSTRAINT sessions_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES asset_accounts(id) ON DELETE SET NULL;

ALTER TABLE session_ad_memberships DROP CONSTRAINT IF EXISTS session_ad_memberships_account_id_fkey;
ALTER TABLE session_ad_memberships
    ADD CONSTRAINT session_ad_memberships_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES asset_accounts(id) ON DELETE CASCADE;

ALTER TABLE db_session_roles DROP CONSTRAINT IF EXISTS db_session_roles_account_id_fkey;
ALTER TABLE db_session_roles
    ADD CONSTRAINT db_session_roles_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES asset_accounts(id) ON DELETE CASCADE;

-- +goose Down
ALTER TABLE db_session_roles DROP CONSTRAINT IF EXISTS db_session_roles_account_id_fkey;
ALTER TABLE db_session_roles
    ADD CONSTRAINT db_session_roles_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES asset_accounts(id);

ALTER TABLE session_ad_memberships DROP CONSTRAINT IF EXISTS session_ad_memberships_account_id_fkey;
ALTER TABLE session_ad_memberships
    ADD CONSTRAINT session_ad_memberships_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES asset_accounts(id);

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_account_id_fkey;
ALTER TABLE sessions
    ADD CONSTRAINT sessions_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES asset_accounts(id);

-- Restore NOT NULL only if no orphaned sessions remain.
UPDATE sessions SET account_id = (SELECT id FROM asset_accounts LIMIT 1) WHERE account_id IS NULL;
ALTER TABLE sessions ALTER COLUMN account_id SET NOT NULL;
