-- +goose Up

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_session_events_type_ts
    ON session_events (event_type, ts DESC);

CREATE INDEX IF NOT EXISTS idx_session_events_payload_trgm
    ON session_events USING GIN ((payload::text) gin_trgm_ops);

-- +goose Down

DROP INDEX IF EXISTS idx_session_events_payload_trgm;
DROP INDEX IF EXISTS idx_session_events_type_ts;
