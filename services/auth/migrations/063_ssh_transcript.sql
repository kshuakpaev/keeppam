-- +goose Up

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS transcript_indexed_at TIMESTAMPTZ;

-- +goose Down

ALTER TABLE sessions DROP COLUMN IF EXISTS transcript_indexed_at;
