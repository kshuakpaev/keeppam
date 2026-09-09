-- +goose Up
-- Catalog of free models: remember chosen preset and optional runtime API key.

ALTER TABLE ai_settings
    ADD COLUMN IF NOT EXISTS preset TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS api_key_enc BYTEA;

-- +goose Down
ALTER TABLE ai_settings DROP COLUMN IF EXISTS api_key_enc;
ALTER TABLE ai_settings DROP COLUMN IF EXISTS preset;
