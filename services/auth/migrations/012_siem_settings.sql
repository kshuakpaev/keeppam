-- +goose Up

CREATE TABLE IF NOT EXISTS siem_settings (
    id                     INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled                BOOLEAN NOT NULL DEFAULT FALSE,
    transport              TEXT NOT NULL DEFAULT 'off'
                           CHECK (transport IN ('off', 'syslog_udp', 'syslog_tcp', 'webhook')),
    syslog_addr            TEXT NOT NULL DEFAULT '',
    syslog_tag             TEXT NOT NULL DEFAULT 'keeppam',
    syslog_facility        INT NOT NULL DEFAULT 16, -- local0
    webhook_url            TEXT NOT NULL DEFAULT '',
    webhook_auth_header_enc BYTEA,
    format                 TEXT NOT NULL DEFAULT 'json'
                           CHECK (format IN ('json', 'cef')),
    batch_size             INT NOT NULL DEFAULT 100 CHECK (batch_size BETWEEN 1 AND 1000),
    poll_interval_sec      INT NOT NULL DEFAULT 10 CHECK (poll_interval_sec BETWEEN 1 AND 3600),
    cursor_ts              TIMESTAMPTZ,
    cursor_id              UUID,
    last_error             TEXT NOT NULL DEFAULT '',
    last_export_at         TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by             UUID REFERENCES users(id)
);

INSERT INTO siem_settings (id) VALUES (1)
ON CONFLICT DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS siem_settings;
