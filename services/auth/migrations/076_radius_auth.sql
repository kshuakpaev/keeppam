-- +goose Up

ALTER TABLE auth_settings DROP CONSTRAINT IF EXISTS auth_settings_mode_check;
ALTER TABLE auth_settings ADD CONSTRAINT auth_settings_mode_check
    CHECK (mode IN ('local', 'oidc', 'ldap', 'saml', 'radius'));

ALTER TABLE auth_settings
    ADD COLUMN IF NOT EXISTS radius_host TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS radius_nas_id TEXT NOT NULL DEFAULT 'keeppam',
    ADD COLUMN IF NOT EXISTS radius_timeout_sec INT NOT NULL DEFAULT 5,
    ADD COLUMN IF NOT EXISTS radius_secret_enc BYTEA,
    ADD COLUMN IF NOT EXISTS radius_auto_provision BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS radius_skip_mfa BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS radius_default_role TEXT NOT NULL DEFAULT 'operator';

-- +goose Down

ALTER TABLE auth_settings DROP CONSTRAINT IF EXISTS auth_settings_mode_check;
ALTER TABLE auth_settings ADD CONSTRAINT auth_settings_mode_check
    CHECK (mode IN ('local', 'oidc', 'ldap', 'saml'));

ALTER TABLE auth_settings
    DROP COLUMN IF EXISTS radius_host,
    DROP COLUMN IF EXISTS radius_nas_id,
    DROP COLUMN IF EXISTS radius_timeout_sec,
    DROP COLUMN IF EXISTS radius_secret_enc,
    DROP COLUMN IF EXISTS radius_auto_provision,
    DROP COLUMN IF EXISTS radius_skip_mfa,
    DROP COLUMN IF EXISTS radius_default_role;
