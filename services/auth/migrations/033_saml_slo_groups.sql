-- +goose Up

ALTER TABLE auth_settings
    ADD COLUMN IF NOT EXISTS saml_group_attr TEXT NOT NULL DEFAULT 'groups',
    ADD COLUMN IF NOT EXISTS saml_group_role_map JSONB NOT NULL DEFAULT '{}'::jsonb;

-- +goose Down
ALTER TABLE auth_settings DROP COLUMN IF EXISTS saml_group_role_map;
ALTER TABLE auth_settings DROP COLUMN IF EXISTS saml_group_attr;
