-- +goose Up

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS firewall_probe_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS firewall_probe_reachable BOOLEAN;

ALTER TABLE firewall_settings
    ADD COLUMN IF NOT EXISTS probe_url TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS awx_launch_url TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS awx_token_enc BYTEA,
    ADD COLUMN IF NOT EXISTS awx_auto_push BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS last_probe_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_push_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_push_error TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE firewall_settings
    DROP COLUMN IF EXISTS last_push_error,
    DROP COLUMN IF EXISTS last_push_at,
    DROP COLUMN IF EXISTS last_probe_at,
    DROP COLUMN IF EXISTS awx_auto_push,
    DROP COLUMN IF EXISTS awx_token_enc,
    DROP COLUMN IF EXISTS awx_launch_url,
    DROP COLUMN IF EXISTS probe_url;

ALTER TABLE assets
    DROP COLUMN IF EXISTS firewall_probe_reachable,
    DROP COLUMN IF EXISTS firewall_probe_at;
