-- +goose Up

-- Named reusable Policy object (WHEN / FROM / HOW / CONTEXT).
-- WHO + WHAT remain on asset_access_bindings (user/role + asset + optional TTL).

CREATE TABLE access_policies (
    id                      UUID PRIMARY KEY,
    name                    TEXT NOT NULL UNIQUE,
    description             TEXT NOT NULL DEFAULT '',
    time_start              TIME,
    time_end                TIME,
    days_of_week            INT NOT NULL DEFAULT 127
                            CHECK (days_of_week >= 0 AND days_of_week <= 127),
    required_tags           TEXT[] NOT NULL DEFAULT '{}',
    require_ticket          BOOLEAN NOT NULL DEFAULT FALSE,
    require_reason          BOOLEAN NOT NULL DEFAULT FALSE,
    allowed_cidrs           TEXT[] NOT NULL DEFAULT '{}',
    allowed_countries       TEXT[] NOT NULL DEFAULT '{}',
    allowed_devices         TEXT[] NOT NULL DEFAULT '{}',
    allowed_namespaces      TEXT[] NOT NULL DEFAULT '{}',
    command_policy_pack_id  UUID REFERENCES command_policy_packs(id) ON DELETE SET NULL,
    sql_policy_pack_id      UUID REFERENCES sql_policy_packs(id) ON DELETE SET NULL,
    http_policy_pack_id     UUID REFERENCES http_policy_packs(id) ON DELETE SET NULL,
    max_risk                INT NOT NULL DEFAULT 0 CHECK (max_risk BETWEEN 0 AND 100),
    risk_action             TEXT NOT NULL DEFAULT 'deny'
                            CHECK (risk_action IN ('deny', 'require_approval')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by              UUID REFERENCES users(id)
);

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS access_policy_id UUID REFERENCES access_policies(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_acl_access_policy ON asset_access_bindings (access_policy_id)
    WHERE access_policy_id IS NOT NULL;

INSERT INTO access_policies (id, name, description, time_start, time_end, days_of_week) VALUES
('01900000-0000-7000-8000-000000000080', 'office-hours',
 'Рабочие часы UTC: пн–пт 09:00–18:00', '09:00', '18:00', 62);

INSERT INTO access_policies (id, name, description, allowed_cidrs, allowed_devices) VALUES
('01900000-0000-7000-8000-000000000081', 'lan-webauthn',
 'Только RFC1918 и устройство WEBAUTHN',
 ARRAY['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
 ARRAY['WEBAUTHN']);

INSERT INTO access_policies (id, name, description, command_policy_pack_id, max_risk, risk_action) VALUES
('01900000-0000-7000-8000-000000000082', 'ssh-readonly',
 'JEA readonly-linux и порог риска 40',
 '01900000-0000-7000-8000-000000000060', 40, 'deny');

-- +goose Down
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS access_policy_id;
DROP TABLE IF EXISTS access_policies;
