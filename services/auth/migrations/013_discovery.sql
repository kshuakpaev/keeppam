-- +goose Up

CREATE TABLE discovery_jobs (
    id              UUID PRIMARY KEY,
    cidr            TEXT NOT NULL,
    ports           TEXT NOT NULL DEFAULT '22,3389,5900',
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'running', 'done', 'failed', 'cancelled')),
    total_hosts     INT NOT NULL DEFAULT 0,
    scanned_hosts   INT NOT NULL DEFAULT 0,
    open_ports      INT NOT NULL DEFAULT 0,
    error           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    created_by      UUID REFERENCES users(id)
);

CREATE TABLE discovery_candidates (
    id                UUID PRIMARY KEY,
    job_id            UUID NOT NULL REFERENCES discovery_jobs(id) ON DELETE CASCADE,
    address           TEXT NOT NULL,
    port              INT NOT NULL,
    protocol          TEXT NOT NULL,
    imported_asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (job_id, address, port)
);

CREATE INDEX idx_discovery_jobs_status ON discovery_jobs (status, created_at DESC);
CREATE INDEX idx_discovery_candidates_job ON discovery_candidates (job_id, created_at DESC);

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-00000000001e', 'discovery.read', 'View discovery jobs and candidates'),
    ('01900000-0000-7000-8000-00000000001f', 'discovery.run', 'Run network discovery scans')
ON CONFLICT DO NOTHING;

-- admin: read + run
INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name IN ('discovery.read', 'discovery.run')
ON CONFLICT DO NOTHING;

-- operator / auditor: read
INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000002', id FROM permissions
WHERE name = 'discovery.read'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000003', id FROM permissions
WHERE name = 'discovery.read'
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM role_permissions WHERE permission_id IN (
    '01900000-0000-7000-8000-00000000001e',
    '01900000-0000-7000-8000-00000000001f'
);
DELETE FROM permissions WHERE name IN ('discovery.read', 'discovery.run');
DROP TABLE IF EXISTS discovery_candidates;
DROP TABLE IF EXISTS discovery_jobs;
