-- +goose Up

CREATE TABLE command_policy_packs (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    mode        TEXT NOT NULL DEFAULT 'allowlist'
                CHECK (mode IN ('allowlist', 'denylist')),
    -- glob-like patterns matched against full command line (case-insensitive), e.g. 'ls*', 'cat /etc/*'
    patterns    TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS command_policy_pack_id UUID REFERENCES command_policy_packs(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_acl_cmd_pack ON asset_access_bindings (command_policy_pack_id)
    WHERE command_policy_pack_id IS NOT NULL;

INSERT INTO command_policy_packs (id, name, description, mode, patterns) VALUES
('01900000-0000-7000-8000-000000000060', 'readonly-linux',
 'Только просмотр: ls/cat/less/grep/df/ps и т.п.', 'allowlist',
 ARRAY['ls','ls *','pwd','whoami','id','date','uname*','cat *','less *','more *','head *','tail *','grep *','egrep *','df*','du*','free*','ps*','top','htop','uptime','env','printenv*','which *','type *','file *','stat *','wc *','echo *','clear','history']),
('01900000-0000-7000-8000-000000000061', 'block-destructive',
 'Запрет опасных команд (rm, dd, mkfs, shutdown...)', 'denylist',
 ARRAY['rm *','rm','dd *','dd','mkfs*','fdisk*','shutdown*','reboot*','halt*','poweroff*','mkfs.*','wipefs*',':(){ :|:& };:*','chmod -R /*','chown -R /*']);

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-000000000062', 'jea.read', 'View command policy packs'),
    ('01900000-0000-7000-8000-000000000063', 'jea.write', 'Manage command policy packs')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions
WHERE name IN ('jea.read', 'jea.write')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-000000000062')
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM role_permissions WHERE permission_id IN (
    '01900000-0000-7000-8000-000000000062',
    '01900000-0000-7000-8000-000000000063'
);
DELETE FROM permissions WHERE name IN ('jea.read', 'jea.write');
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS command_policy_pack_id;
DROP TABLE IF EXISTS command_policy_packs;
