-- +goose Up

CREATE TABLE retention_policies (
    id                      UUID PRIMARY KEY,
    name                    TEXT NOT NULL UNIQUE DEFAULT 'default',
    audit_retention_days    INT NOT NULL DEFAULT 365
                            CHECK (audit_retention_days >= 0),
    session_retention_days  INT NOT NULL DEFAULT 180
                            CHECK (session_retention_days >= 0),
    recording_retention_days INT NOT NULL DEFAULT 90
                            CHECK (recording_retention_days >= 0),
    -- 0 = never auto-purge that class
    purge_enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by              UUID REFERENCES users(id)
);

INSERT INTO retention_policies (id, name, audit_retention_days, session_retention_days, recording_retention_days, purge_enabled)
VALUES ('01900000-0000-7000-8000-000000000050', 'default', 365, 180, 90, TRUE);

CREATE TABLE legal_holds (
    id            UUID PRIMARY KEY,
    resource_type TEXT NOT NULL
                  CHECK (resource_type IN ('session', 'asset', 'user', 'global')),
    resource_id   TEXT NOT NULL DEFAULT '',
    reason        TEXT NOT NULL DEFAULT '',
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by    UUID REFERENCES users(id),
    released_at   TIMESTAMPTZ,
    released_by   UUID REFERENCES users(id)
);

CREATE INDEX idx_legal_holds_active ON legal_holds (active, resource_type);

CREATE TABLE compliance_packs (
    id           TEXT PRIMARY KEY,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    controls     JSONB NOT NULL DEFAULT '[]',
    -- recommended retention when applied
    audit_days   INT NOT NULL DEFAULT 365,
    session_days INT NOT NULL DEFAULT 180,
    recording_days INT NOT NULL DEFAULT 90,
    sort_order   INT NOT NULL DEFAULT 0
);

CREATE TABLE compliance_state (
    id              UUID PRIMARY KEY,
    active_pack_id  TEXT REFERENCES compliance_packs(id),
    applied_at      TIMESTAMPTZ,
    applied_by      UUID REFERENCES users(id),
    last_purge_at   TIMESTAMPTZ,
    last_purge_stats JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO compliance_state (id) VALUES ('01900000-0000-7000-8000-000000000051');

INSERT INTO compliance_packs (id, title, description, controls, audit_days, session_days, recording_days, sort_order) VALUES
('baseline', 'Baseline PAM', 'Минимальный набор контролей KeepPAM для on-prem',
 '["mfa_admins","session_recording","audit_trail","rbac","retention_configured"]'::jsonb,
 365, 180, 90, 10),
('sox-lite', 'SOX-lite', 'Усиленный retention и 4-eyes/JIT для финансовых контуров',
 '["mfa_admins","session_recording","audit_trail","rbac","retention_configured","jit_approvals","siem_export","legal_hold"]'::jsonb,
 2555, 730, 365, 20),
('pci-lite', 'PCI-lite', 'Сессии к карточным сегментам: короткий recording TTL + обязательный SIEM',
 '["mfa_admins","session_recording","audit_trail","rbac","retention_configured","siem_export","secret_rotation","abac_tags"]'::jsonb,
 365, 90, 30, 30);

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-000000000052', 'compliance.read', 'View compliance packs, retention and legal holds'),
    ('01900000-0000-7000-8000-000000000053', 'compliance.write', 'Apply packs, change retention, manage legal holds')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name IN ('compliance.read', 'compliance.write')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-000000000052')
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM role_permissions WHERE permission_id IN (
    '01900000-0000-7000-8000-000000000052',
    '01900000-0000-7000-8000-000000000053'
);
DELETE FROM permissions WHERE name IN ('compliance.read', 'compliance.write');
DROP TABLE IF EXISTS compliance_state;
DROP TABLE IF EXISTS compliance_packs;
DROP TABLE IF EXISTS legal_holds;
DROP TABLE IF EXISTS retention_policies;
