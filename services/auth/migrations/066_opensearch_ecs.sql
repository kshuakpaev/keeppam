-- +goose Up

ALTER TABLE siem_settings DROP CONSTRAINT IF EXISTS siem_settings_transport_check;
ALTER TABLE siem_settings ADD CONSTRAINT siem_settings_transport_check
    CHECK (transport IN ('off', 'syslog_udp', 'syslog_tcp', 'webhook', 'kafka', 'nats', 'opensearch'));

ALTER TABLE siem_settings DROP CONSTRAINT IF EXISTS siem_settings_format_check;
ALTER TABLE siem_settings ADD CONSTRAINT siem_settings_format_check
    CHECK (format IN ('json', 'cef', 'ecs'));

ALTER TABLE siem_settings
    ADD COLUMN IF NOT EXISTS opensearch_url TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS opensearch_index TEXT NOT NULL DEFAULT 'keeppam-audit';

-- +goose Down

ALTER TABLE siem_settings DROP CONSTRAINT IF EXISTS siem_settings_transport_check;
ALTER TABLE siem_settings ADD CONSTRAINT siem_settings_transport_check
    CHECK (transport IN ('off', 'syslog_udp', 'syslog_tcp', 'webhook', 'kafka', 'nats'));
ALTER TABLE siem_settings DROP CONSTRAINT IF EXISTS siem_settings_format_check;
ALTER TABLE siem_settings ADD CONSTRAINT siem_settings_format_check
    CHECK (format IN ('json', 'cef'));
ALTER TABLE siem_settings DROP COLUMN IF EXISTS opensearch_url;
ALTER TABLE siem_settings DROP COLUMN IF EXISTS opensearch_index;
