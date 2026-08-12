-- +goose Up

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_protocol_check;
ALTER TABLE assets ADD CONSTRAINT assets_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'https', 'postgres', 'mysql', 'kubectl'));

ALTER TABLE asset_accounts DROP CONSTRAINT IF EXISTS asset_accounts_auth_method_check;
ALTER TABLE asset_accounts ADD CONSTRAINT asset_accounts_auth_method_check
    CHECK (auth_method IN ('password', 'ssh_key', 'kubeconfig', 'sa_token'));

-- +goose Down
ALTER TABLE asset_accounts DROP CONSTRAINT IF EXISTS asset_accounts_auth_method_check;
ALTER TABLE asset_accounts ADD CONSTRAINT asset_accounts_auth_method_check
    CHECK (auth_method IN ('password', 'ssh_key'));

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_protocol_check;
ALTER TABLE assets ADD CONSTRAINT assets_protocol_check
    CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'https', 'postgres', 'mysql'));
