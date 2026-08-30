-- +goose Up
-- NIT §5: FTP protocol, asset owner role, session_files ftp.

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_protocol_check;
ALTER TABLE assets ADD CONSTRAINT assets_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'https', 'postgres', 'mysql', 'mssql', 'kubectl', 'telnet', 'tn3270', 'citrix', 'oracle', 'ftp'));

ALTER TABLE assets ADD COLUMN IF NOT EXISTS owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_assets_owner_user ON assets (owner_user_id) WHERE owner_user_id IS NOT NULL;

ALTER TABLE session_files DROP CONSTRAINT IF EXISTS session_files_protocol_check;
ALTER TABLE session_files ADD CONSTRAINT session_files_protocol_check
    CHECK (protocol IN ('scp', 'sftp', 'ftp'));

INSERT INTO roles (id, name, description) VALUES
    ('01900000-0000-7000-8000-000000000005', 'owner', 'Owner of assigned IT assets: ACL and sessions on own systems')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000005', id FROM permissions
WHERE name IN (
    'self.read',
    'assets.read',
    'assets.write',
    'assets.acl',
    'sessions.read',
    'sessions.connect',
    'sessions.files.read',
    'access.request',
    'access.approve',
    'audit.read',
    'jea.read'
)
ON CONFLICT DO NOTHING;

COMMENT ON COLUMN assets.owner_user_id IS 'PAM user (role owner) responsible for this target system';

-- +goose Down
DELETE FROM role_permissions WHERE role_id = '01900000-0000-7000-8000-000000000005';
DELETE FROM user_role_bindings WHERE role_id = '01900000-0000-7000-8000-000000000005';
DELETE FROM roles WHERE id = '01900000-0000-7000-8000-000000000005';

ALTER TABLE session_files DROP CONSTRAINT IF EXISTS session_files_protocol_check;
ALTER TABLE session_files ADD CONSTRAINT session_files_protocol_check
    CHECK (protocol IN ('scp', 'sftp'));

ALTER TABLE assets DROP COLUMN IF EXISTS owner_user_id;

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_protocol_check;
ALTER TABLE assets ADD CONSTRAINT assets_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'https', 'postgres', 'mysql', 'mssql', 'kubectl', 'telnet', 'tn3270', 'citrix', 'oracle'));
