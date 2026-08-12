-- +goose Up

ALTER TABLE assets ADD COLUMN IF NOT EXISTS database_name TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS database_name TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE sessions DROP COLUMN IF EXISTS database_name;
ALTER TABLE assets DROP COLUMN IF EXISTS database_name;
