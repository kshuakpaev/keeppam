-- +goose Up

-- T-34 RDS RemoteApp: Guacamole remote-app / dir / args on RDP assets.
ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS rdp_remote_app TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS rdp_remote_app_dir TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS rdp_remote_app_args TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE assets DROP COLUMN IF EXISTS rdp_remote_app_args;
ALTER TABLE assets DROP COLUMN IF EXISTS rdp_remote_app_dir;
ALTER TABLE assets DROP COLUMN IF EXISTS rdp_remote_app;
