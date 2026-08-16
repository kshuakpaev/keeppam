-- +goose Up

-- PAM groups are org units for WHO on ACL. Roles stay platform permissions.

CREATE TABLE groups (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  UUID REFERENCES users(id)
);

CREATE TABLE user_group_members (
    user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX idx_user_group_members_group ON user_group_members (group_id);

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS group_id UUID REFERENCES groups(id) ON DELETE CASCADE;

DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT conname, pg_get_constraintdef(oid) AS def
    FROM pg_constraint
    WHERE conrelid = 'asset_access_bindings'::regclass AND contype = 'c'
  LOOP
    IF r.def ILIKE '%user_id%' AND r.def ILIKE '%role_id%' AND r.def NOT ILIKE '%risk_action%' THEN
      EXECUTE format('ALTER TABLE asset_access_bindings DROP CONSTRAINT %I', r.conname);
    END IF;
  END LOOP;
END $$;

ALTER TABLE asset_access_bindings
    ADD CONSTRAINT asset_access_bindings_subject_check
    CHECK (
        (user_id IS NOT NULL)::int +
        (role_id IS NOT NULL)::int +
        (group_id IS NOT NULL)::int = 1
    );

CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_access_group
    ON asset_access_bindings (asset_id, group_id)
    WHERE group_id IS NOT NULL AND expires_at IS NULL;

INSERT INTO groups (id, name, description) VALUES
('01900000-0000-7000-8000-000000000090', 'dba', 'Доступ к БД (ACL на группу, не на каждого DBA)'),
('01900000-0000-7000-8000-000000000091', 'linux-ops', 'Операторы Linux-хостов')
ON CONFLICT (name) DO NOTHING;

-- +goose Down

ALTER TABLE asset_access_bindings DROP CONSTRAINT IF EXISTS asset_access_bindings_subject_check;
DROP INDEX IF EXISTS idx_asset_access_group;
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS group_id;
ALTER TABLE asset_access_bindings
    ADD CONSTRAINT asset_access_bindings_check
    CHECK (user_id IS NOT NULL OR role_id IS NOT NULL);
ALTER TABLE asset_access_bindings
    ADD CONSTRAINT asset_access_bindings_check1
    CHECK (NOT (user_id IS NOT NULL AND role_id IS NOT NULL));

DROP TABLE IF EXISTS user_group_members;
DROP TABLE IF EXISTS groups;
