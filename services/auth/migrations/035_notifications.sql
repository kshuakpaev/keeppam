-- +goose Up

CREATE TABLE IF NOT EXISTS notifications (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    title       TEXT NOT NULL,
    body        TEXT NOT NULL DEFAULT '',
    ref_type    TEXT NOT NULL DEFAULT '',
    ref_id      TEXT NOT NULL DEFAULT '',
    read_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS notifications_user_unread
    ON notifications (user_id, created_at DESC)
    WHERE read_at IS NULL;

CREATE INDEX IF NOT EXISTS notifications_user_all
    ON notifications (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS notify_settings (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    webhook_url     TEXT NOT NULL DEFAULT '',
    auth_header_enc BYTEA,
    timeout_sec     INT NOT NULL DEFAULT 5 CHECK (timeout_sec BETWEEN 1 AND 30),
    last_error      TEXT NOT NULL DEFAULT '',
    last_sent_at    TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by      UUID REFERENCES users(id)
);

INSERT INTO notify_settings (id) VALUES (1) ON CONFLICT DO NOTHING;

-- +goose Down

DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS notify_settings;
