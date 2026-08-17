-- +goose Up

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS firewall_applied_at TIMESTAMPTZ;

-- +goose Down

ALTER TABLE assets DROP COLUMN IF EXISTS firewall_applied_at;
