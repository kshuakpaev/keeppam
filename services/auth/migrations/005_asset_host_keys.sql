-- +goose Up

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS host_key_algo TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS host_key_blob BYTEA,
    ADD COLUMN IF NOT EXISTS host_key_fp TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS host_key_learned_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE assets
    DROP COLUMN IF EXISTS host_key_learned_at,
    DROP COLUMN IF EXISTS host_key_fp,
    DROP COLUMN IF EXISTS host_key_blob,
    DROP COLUMN IF EXISTS host_key_algo;
