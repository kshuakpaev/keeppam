-- +goose Up

-- Snapshot of access context at session start (concept1: unified recording metadata).
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS risk_score INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS risk_factors TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS labels TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS access_policy_id UUID,
    ADD COLUMN IF NOT EXISTS client_country TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON sessions (started_at DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_sessions_labels ON sessions USING GIN (labels);

-- +goose Down
ALTER TABLE sessions DROP COLUMN IF EXISTS risk_score;
ALTER TABLE sessions DROP COLUMN IF EXISTS risk_factors;
ALTER TABLE sessions DROP COLUMN IF EXISTS labels;
ALTER TABLE sessions DROP COLUMN IF EXISTS access_policy_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS client_country;
DROP INDEX IF EXISTS idx_sessions_started_at;
DROP INDEX IF EXISTS idx_sessions_labels;
