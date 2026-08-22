-- +goose Up

CREATE TABLE IF NOT EXISTS nac_settings (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    mode            TEXT NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'audit', 'enforce')),
    api_url         TEXT NOT NULL DEFAULT '',
    api_token_enc   BYTEA,
    vendor          TEXT NOT NULL DEFAULT 'generic' CHECK (vendor IN ('generic', 'cisco_ise')),
    timeout_ms      INT NOT NULL DEFAULT 3000 CHECK (timeout_ms BETWEEN 500 AND 30000),
    last_check_at   TIMESTAMPTZ,
    last_error      TEXT NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO nac_settings (id) VALUES (1) ON CONFLICT DO NOTHING;

-- +goose Down

DROP TABLE IF EXISTS nac_settings;
