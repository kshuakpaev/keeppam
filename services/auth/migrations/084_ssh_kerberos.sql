-- +goose Up

ALTER TABLE ssh_settings DROP CONSTRAINT IF EXISTS ssh_settings_ssh_auth_mode_check;
ALTER TABLE ssh_settings
    ADD CONSTRAINT ssh_settings_ssh_auth_mode_check
    CHECK (ssh_auth_mode IN ('vault_secret', 'ssh_cert', 'gssapi'));

ALTER TABLE ssh_settings
    ADD COLUMN IF NOT EXISTS krb5_realm TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS krb5_config TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS krb5_principal TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS krb5_keytab_enc BYTEA,
    ADD COLUMN IF NOT EXISTS krb5_spn_template TEXT NOT NULL DEFAULT 'host/%h';

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS krb_spn TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE assets DROP COLUMN IF EXISTS krb_spn;
ALTER TABLE ssh_settings
    DROP COLUMN IF EXISTS krb5_realm,
    DROP COLUMN IF EXISTS krb5_config,
    DROP COLUMN IF EXISTS krb5_principal,
    DROP COLUMN IF EXISTS krb5_keytab_enc,
    DROP COLUMN IF EXISTS krb5_spn_template;
ALTER TABLE ssh_settings DROP CONSTRAINT IF EXISTS ssh_settings_ssh_auth_mode_check;
ALTER TABLE ssh_settings
    ADD CONSTRAINT ssh_settings_ssh_auth_mode_check
    CHECK (ssh_auth_mode IN ('vault_secret', 'ssh_cert'));
