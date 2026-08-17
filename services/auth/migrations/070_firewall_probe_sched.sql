-- +goose Up

ALTER TABLE firewall_settings
    ADD COLUMN IF NOT EXISTS probe_interval_hours INT NOT NULL DEFAULT 0;

ALTER TABLE firewall_settings
    DROP CONSTRAINT IF EXISTS firewall_settings_probe_interval_hours_check;

ALTER TABLE firewall_settings
    ADD CONSTRAINT firewall_settings_probe_interval_hours_check
    CHECK (probe_interval_hours >= 0 AND probe_interval_hours <= 168);

UPDATE firewall_settings
SET probe_url = 'http://firewall-probe:8100/probe'
WHERE id = 1 AND COALESCE(probe_url, '') = '';

-- +goose Down

ALTER TABLE firewall_settings DROP CONSTRAINT IF EXISTS firewall_settings_probe_interval_hours_check;
ALTER TABLE firewall_settings DROP COLUMN IF EXISTS probe_interval_hours;
