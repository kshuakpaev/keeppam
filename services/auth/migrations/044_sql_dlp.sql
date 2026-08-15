-- +goose Up

ALTER TABLE sql_policy_packs
    ADD COLUMN IF NOT EXISTS max_rows INT NOT NULL DEFAULT 500
        CHECK (max_rows BETWEEN 1 AND 100000),
    ADD COLUMN IF NOT EXISTS dlp_action TEXT NOT NULL DEFAULT 'truncate'
        CHECK (dlp_action IN ('truncate', 'deny'));

-- +goose Down

ALTER TABLE sql_policy_packs DROP COLUMN IF EXISTS max_rows;
ALTER TABLE sql_policy_packs DROP COLUMN IF EXISTS dlp_action;
