-- +goose Up

CREATE TABLE IF NOT EXISTS eidas_settings (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    mode            TEXT NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'advanced', 'qualified')),
    profile         TEXT NOT NULL DEFAULT 'eidas' CHECK (profile IN ('eidas', 'fstec')),
    require_b_lta   BOOLEAN NOT NULL DEFAULT TRUE,
    pkcs11_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
    pkcs11_module   TEXT NOT NULL DEFAULT '',
    pkcs11_label    TEXT NOT NULL DEFAULT '',
    pkcs11_pin_enc  BYTEA,
    last_check_at   TIMESTAMPTZ,
    last_error      TEXT NOT NULL DEFAULT '',
    cert_cn         TEXT NOT NULL DEFAULT '',
    cert_qualified  BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO eidas_settings (id) VALUES (1) ON CONFLICT DO NOTHING;

-- +goose Down

DROP TABLE IF EXISTS eidas_settings;
