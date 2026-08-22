-- +goose Up

CREATE TABLE IF NOT EXISTS ueba_ml_settings (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    mode            TEXT NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'audit', 'live')),
    peer_group      BOOLEAN NOT NULL DEFAULT TRUE,
    ml_threshold    INT NOT NULL DEFAULT 65 CHECK (ml_threshold BETWEEN 30 AND 95),
    live_interval_s INT NOT NULL DEFAULT 60 CHECK (live_interval_s BETWEEN 15 AND 600),
    last_run_at     TIMESTAMPTZ,
    last_error      TEXT NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO ueba_ml_settings (id) VALUES (1) ON CONFLICT DO NOTHING;

-- +goose Down

DROP TABLE IF EXISTS ueba_ml_settings;
