-- +goose Up

ALTER TABLE notify_settings
    ADD COLUMN IF NOT EXISTS smtp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS smtp_host TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS smtp_port INT NOT NULL DEFAULT 587,
    ADD COLUMN IF NOT EXISTS smtp_tls TEXT NOT NULL DEFAULT 'starttls',
    ADD COLUMN IF NOT EXISTS smtp_tls_insecure BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS smtp_username TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS smtp_password_enc BYTEA,
    ADD COLUMN IF NOT EXISTS smtp_from TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS smtp_last_error TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS smtp_last_sent_at TIMESTAMPTZ;

ALTER TABLE notify_settings DROP CONSTRAINT IF EXISTS notify_settings_smtp_port_check;
ALTER TABLE notify_settings ADD CONSTRAINT notify_settings_smtp_port_check
    CHECK (smtp_port BETWEEN 1 AND 65535);

ALTER TABLE notify_settings DROP CONSTRAINT IF EXISTS notify_settings_smtp_tls_check;
ALTER TABLE notify_settings ADD CONSTRAINT notify_settings_smtp_tls_check
    CHECK (smtp_tls IN ('starttls', 'tls', 'none'));

-- +goose Down

ALTER TABLE notify_settings DROP CONSTRAINT IF EXISTS notify_settings_smtp_port_check;
ALTER TABLE notify_settings DROP CONSTRAINT IF EXISTS notify_settings_smtp_tls_check;
ALTER TABLE notify_settings
    DROP COLUMN IF EXISTS smtp_enabled,
    DROP COLUMN IF EXISTS smtp_host,
    DROP COLUMN IF EXISTS smtp_port,
    DROP COLUMN IF EXISTS smtp_tls,
    DROP COLUMN IF EXISTS smtp_tls_insecure,
    DROP COLUMN IF EXISTS smtp_username,
    DROP COLUMN IF EXISTS smtp_password_enc,
    DROP COLUMN IF EXISTS smtp_from,
    DROP COLUMN IF EXISTS smtp_last_error,
    DROP COLUMN IF EXISTS smtp_last_sent_at;
