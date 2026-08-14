-- +goose Up

CREATE TABLE IF NOT EXISTS audit_batches (
    id             UUID PRIMARY KEY,
    seq            BIGINT NOT NULL UNIQUE,
    from_ts        TIMESTAMPTZ NOT NULL,
    to_ts          TIMESTAMPTZ NOT NULL,
    first_id       UUID NOT NULL,
    last_id        UUID NOT NULL,
    event_count    INT NOT NULL CHECK (event_count > 0),
    first_hash     TEXT NOT NULL,
    last_hash      TEXT NOT NULL,
    prev_batch_mac TEXT NOT NULL DEFAULT '',
    mac            TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_batches_seq ON audit_batches (seq DESC);

-- +goose Down

DROP TABLE IF EXISTS audit_batches;
