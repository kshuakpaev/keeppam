-- +goose Up

ALTER TABLE firewall_settings
    ADD COLUMN IF NOT EXISTS probe_quorum INT NOT NULL DEFAULT 1;

ALTER TABLE firewall_settings
    DROP CONSTRAINT IF EXISTS firewall_settings_probe_quorum_check;

ALTER TABLE firewall_settings
    ADD CONSTRAINT firewall_settings_probe_quorum_check
    CHECK (probe_quorum >= 1 AND probe_quorum <= 16);

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS probe_segment TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS firewall_probe_agents (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    segment TEXT NOT NULL DEFAULT '',
    probe_url TEXT NOT NULL,
    token_enc BYTEA,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order INT NOT NULL DEFAULT 0,
    last_health_at TIMESTAMPTZ,
    last_health_ok BOOLEAN,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT firewall_probe_agents_name_chk CHECK (name ~ '^[a-z][a-z0-9_-]{0,31}$'),
    UNIQUE (name)
);

CREATE INDEX IF NOT EXISTS idx_firewall_probe_agents_sort ON firewall_probe_agents(sort_order, name);

INSERT INTO firewall_probe_agents (id, name, segment, probe_url, enabled, sort_order)
SELECT gen_random_uuid(), 'default', '', probe_url, TRUE, 0
FROM firewall_settings
WHERE id = 1 AND COALESCE(probe_url, '') <> ''
ON CONFLICT (name) DO NOTHING;

INSERT INTO firewall_probe_agents (id, name, segment, probe_url, enabled, sort_order)
SELECT gen_random_uuid(), 'segment-b', 'lab', 'http://firewall-probe-b:8101/probe', TRUE, 1
FROM firewall_settings
WHERE id = 1 AND EXISTS (
    SELECT 1 FROM firewall_probe_agents WHERE name = 'default'
)
ON CONFLICT (name) DO NOTHING;

-- +goose Down

DROP TABLE IF EXISTS firewall_probe_agents;
ALTER TABLE assets DROP COLUMN IF EXISTS probe_segment;
ALTER TABLE firewall_settings DROP CONSTRAINT IF EXISTS firewall_settings_probe_quorum_check;
ALTER TABLE firewall_settings DROP COLUMN IF EXISTS probe_quorum;
