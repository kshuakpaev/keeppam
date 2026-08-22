-- +goose Up
-- SOW-ORACLE: protocol=oracle for vault password rotate/sync (thin driver + optional sqlplus).

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_protocol_check;
ALTER TABLE assets ADD CONSTRAINT assets_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'https', 'postgres', 'mysql', 'mssql', 'kubectl', 'telnet', 'tn3270', 'citrix', 'oracle'));

COMMENT ON COLUMN assets.database_name IS 'DB name (PG/MySQL/MSSQL) or Oracle service/SID (database_name on oracle assets)';

-- +goose Down
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_protocol_check;
ALTER TABLE assets ADD CONSTRAINT assets_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'https', 'postgres', 'mysql', 'mssql', 'kubectl', 'telnet', 'tn3270', 'citrix'));
