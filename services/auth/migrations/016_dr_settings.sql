-- +goose Up

CREATE TABLE dr_settings (
    id                 INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    site_name          TEXT NOT NULL DEFAULT 'primary',
    role               TEXT NOT NULL DEFAULT 'primary'
                       CHECK (role IN ('primary', 'dr', 'standalone')),
    rpo_minutes        INT NOT NULL DEFAULT 60 CHECK (rpo_minutes > 0),
    rto_minutes        INT NOT NULL DEFAULT 240 CHECK (rto_minutes > 0),
    replica_dsn_hint   TEXT NOT NULL DEFAULT '',
    backup_dir         TEXT NOT NULL DEFAULT '/tmp/keeppam-backups',
    last_backup_at     TIMESTAMPTZ,
    last_backup_path   TEXT NOT NULL DEFAULT '',
    last_backup_bytes  BIGINT NOT NULL DEFAULT 0,
    last_backup_status TEXT NOT NULL DEFAULT '',
    last_drill_at      TIMESTAMPTZ,
    last_drill_notes   TEXT NOT NULL DEFAULT '',
    last_drill_ok      BOOLEAN,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO dr_settings (id) VALUES (1) ON CONFLICT DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS dr_settings;
