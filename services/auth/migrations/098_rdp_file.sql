-- +goose Up
-- SOW-RDP-FILE: session_files protocol for RDP drive/clipboard capture.

ALTER TABLE session_files DROP CONSTRAINT IF EXISTS session_files_protocol_check;
ALTER TABLE session_files ADD CONSTRAINT session_files_protocol_check
    CHECK (protocol IN ('scp', 'sftp', 'rdp-drive', 'rdp-clipboard'));

COMMENT ON COLUMN session_files.protocol IS 'scp|sftp|rdp-drive|rdp-clipboard';

-- +goose Down
ALTER TABLE session_files DROP CONSTRAINT IF EXISTS session_files_protocol_check;
ALTER TABLE session_files ADD CONSTRAINT session_files_protocol_check
    CHECK (protocol IN ('scp', 'sftp'));
