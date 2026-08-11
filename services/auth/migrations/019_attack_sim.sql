-- +goose Up

CREATE TABLE attack_sim_runs (
    id          UUID PRIMARY KEY,
    started_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    status      TEXT NOT NULL DEFAULT 'running'
                CHECK (status IN ('running', 'passed', 'failed', 'partial')),
    notes       TEXT NOT NULL DEFAULT '',
    summary     JSONB NOT NULL DEFAULT '{}',
    started_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);

CREATE TABLE attack_sim_results (
    id          UUID PRIMARY KEY,
    run_id      UUID NOT NULL REFERENCES attack_sim_runs(id) ON DELETE CASCADE,
    scenario_id TEXT NOT NULL,
    title       TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT 'control',
    status      TEXT NOT NULL CHECK (status IN ('pass', 'fail', 'skip', 'error')),
    detail      TEXT NOT NULL DEFAULT '',
    duration_ms INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_attack_sim_runs_started ON attack_sim_runs (started_at DESC);
CREATE INDEX idx_attack_sim_results_run ON attack_sim_results (run_id);

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-000000000070', 'attacksim.read', 'View attack simulation scenarios and runs'),
    ('01900000-0000-7000-8000-000000000071', 'attacksim.write', 'Run attack simulation program')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name IN ('attacksim.read', 'attacksim.write')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-000000000070')
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM role_permissions WHERE permission_id IN (
    '01900000-0000-7000-8000-000000000070',
    '01900000-0000-7000-8000-000000000071'
);
DELETE FROM permissions WHERE name IN ('attacksim.read', 'attacksim.write');
DROP TABLE IF EXISTS attack_sim_results;
DROP TABLE IF EXISTS attack_sim_runs;
