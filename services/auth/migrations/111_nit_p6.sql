-- +goose Up
-- NIT §6: SIEM LEEF, OAuth 2.0 / DigitalID (authorization code + userinfo, no OIDC discovery).

ALTER TABLE siem_settings DROP CONSTRAINT IF EXISTS siem_settings_format_check;
ALTER TABLE siem_settings ADD CONSTRAINT siem_settings_format_check
    CHECK (format IN ('json', 'cef', 'ecs', 'leef'));

ALTER TABLE auth_settings DROP CONSTRAINT IF EXISTS auth_settings_mode_check;
ALTER TABLE auth_settings ADD CONSTRAINT auth_settings_mode_check
    CHECK (mode IN ('local', 'oidc', 'ldap', 'saml', 'radius', 'oauth'));

ALTER TABLE auth_settings ADD COLUMN IF NOT EXISTS oauth_authorize_url TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_settings ADD COLUMN IF NOT EXISTS oauth_token_url TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_settings ADD COLUMN IF NOT EXISTS oauth_userinfo_url TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_settings ADD COLUMN IF NOT EXISTS oauth_username_claim TEXT NOT NULL DEFAULT 'iin';
ALTER TABLE auth_settings ADD COLUMN IF NOT EXISTS oauth_email_claim TEXT NOT NULL DEFAULT 'email';
ALTER TABLE auth_settings ADD COLUMN IF NOT EXISTS oauth_name_claim TEXT NOT NULL DEFAULT 'name';

COMMENT ON COLUMN auth_settings.oauth_authorize_url IS 'OAuth 2.0 authorize endpoint (Digital ID and other OAuth IdPs without OIDC discovery)';

-- +goose Down
ALTER TABLE siem_settings DROP CONSTRAINT IF EXISTS siem_settings_format_check;
ALTER TABLE siem_settings ADD CONSTRAINT siem_settings_format_check
    CHECK (format IN ('json', 'cef', 'ecs'));

ALTER TABLE auth_settings DROP CONSTRAINT IF EXISTS auth_settings_mode_check;
ALTER TABLE auth_settings ADD CONSTRAINT auth_settings_mode_check
    CHECK (mode IN ('local', 'oidc', 'ldap', 'saml', 'radius'));

ALTER TABLE auth_settings DROP COLUMN IF EXISTS oauth_authorize_url;
ALTER TABLE auth_settings DROP COLUMN IF EXISTS oauth_token_url;
ALTER TABLE auth_settings DROP COLUMN IF EXISTS oauth_userinfo_url;
ALTER TABLE auth_settings DROP COLUMN IF EXISTS oauth_username_claim;
ALTER TABLE auth_settings DROP COLUMN IF EXISTS oauth_email_claim;
ALTER TABLE auth_settings DROP COLUMN IF EXISTS oauth_name_claim;
