-- +goose Up
ALTER TABLE auth_settings
    ADD COLUMN IF NOT EXISTS idle_timeout_min INT NOT NULL DEFAULT 5;

ALTER TABLE auth_settings DROP CONSTRAINT IF EXISTS auth_settings_idle_timeout_min_check;
ALTER TABLE auth_settings
    ADD CONSTRAINT auth_settings_idle_timeout_min_check
    CHECK (idle_timeout_min BETWEEN 1 AND 30);

-- +goose Down
ALTER TABLE auth_settings DROP CONSTRAINT IF EXISTS auth_settings_idle_timeout_min_check;
ALTER TABLE auth_settings DROP COLUMN IF EXISTS idle_timeout_min;
