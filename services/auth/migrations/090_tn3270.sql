-- +goose Up

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_protocol_check;
ALTER TABLE assets ADD CONSTRAINT assets_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'https', 'postgres', 'mysql', 'mssql', 'kubectl', 'telnet', 'tn3270'));

-- +goose Down
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_protocol_check;
ALTER TABLE assets ADD CONSTRAINT assets_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'https', 'postgres', 'mysql', 'mssql', 'kubectl', 'telnet'));
