-- +goose Up

ALTER TABLE auth_settings DROP CONSTRAINT IF EXISTS auth_settings_mode_check;
ALTER TABLE auth_settings ADD CONSTRAINT auth_settings_mode_check
    CHECK (mode IN ('local', 'oidc', 'ldap', 'saml'));

ALTER TABLE auth_settings
    ADD COLUMN IF NOT EXISTS saml_idp_metadata_url TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS saml_idp_entity_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS saml_idp_sso_url TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS saml_idp_cert_pem TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS saml_sp_entity_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS saml_sp_key_enc BYTEA,
    ADD COLUMN IF NOT EXISTS saml_attr_username TEXT NOT NULL DEFAULT 'uid',
    ADD COLUMN IF NOT EXISTS saml_attr_email TEXT NOT NULL DEFAULT 'email',
    ADD COLUMN IF NOT EXISTS saml_attr_display_name TEXT NOT NULL DEFAULT 'displayName',
    ADD COLUMN IF NOT EXISTS saml_auto_provision BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS saml_skip_mfa BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS saml_default_role TEXT NOT NULL DEFAULT 'operator';

-- +goose Down
ALTER TABLE auth_settings
    DROP COLUMN IF EXISTS saml_idp_metadata_url,
    DROP COLUMN IF EXISTS saml_idp_entity_id,
    DROP COLUMN IF EXISTS saml_idp_sso_url,
    DROP COLUMN IF EXISTS saml_idp_cert_pem,
    DROP COLUMN IF EXISTS saml_sp_entity_id,
    DROP COLUMN IF EXISTS saml_sp_key_enc,
    DROP COLUMN IF EXISTS saml_attr_username,
    DROP COLUMN IF EXISTS saml_attr_email,
    DROP COLUMN IF EXISTS saml_attr_display_name,
    DROP COLUMN IF EXISTS saml_auto_provision,
    DROP COLUMN IF EXISTS saml_skip_mfa,
    DROP COLUMN IF EXISTS saml_default_role;

ALTER TABLE auth_settings DROP CONSTRAINT IF EXISTS auth_settings_mode_check;
ALTER TABLE auth_settings ADD CONSTRAINT auth_settings_mode_check
    CHECK (mode IN ('local', 'oidc', 'ldap'));
