-- +goose Up
ALTER TABLE sessions ADD COLUMN last_seen_at TIMESTAMPTZ;
CREATE INDEX idx_sessions_last_seen ON sessions (status, last_seen_at);

-- +goose Down
DROP INDEX IF EXISTS idx_sessions_last_seen;
ALTER TABLE sessions DROP COLUMN IF EXISTS last_seen_at;
