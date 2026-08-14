-- +goose Up

ALTER TABLE siem_settings DROP CONSTRAINT IF EXISTS siem_settings_transport_check;
ALTER TABLE siem_settings ADD CONSTRAINT siem_settings_transport_check
    CHECK (transport IN ('off', 'syslog_udp', 'syslog_tcp', 'webhook', 'kafka', 'nats'));

ALTER TABLE siem_settings
    ADD COLUMN IF NOT EXISTS kafka_brokers TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS kafka_topic TEXT NOT NULL DEFAULT 'keeppam.audit',
    ADD COLUMN IF NOT EXISTS kafka_username TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS kafka_password_enc BYTEA,
    ADD COLUMN IF NOT EXISTS nats_url TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS nats_subject TEXT NOT NULL DEFAULT 'keeppam.audit',
    ADD COLUMN IF NOT EXISTS nats_token_enc BYTEA;

-- +goose Down

ALTER TABLE siem_settings DROP CONSTRAINT IF EXISTS siem_settings_transport_check;
ALTER TABLE siem_settings ADD CONSTRAINT siem_settings_transport_check
    CHECK (transport IN ('off', 'syslog_udp', 'syslog_tcp', 'webhook'));
ALTER TABLE siem_settings
    DROP COLUMN IF EXISTS kafka_brokers,
    DROP COLUMN IF EXISTS kafka_topic,
    DROP COLUMN IF EXISTS kafka_username,
    DROP COLUMN IF EXISTS kafka_password_enc,
    DROP COLUMN IF EXISTS nats_url,
    DROP COLUMN IF EXISTS nats_subject,
    DROP COLUMN IF EXISTS nats_token_enc;
