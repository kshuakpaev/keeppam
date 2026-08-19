-- +goose Up

CREATE TABLE IF NOT EXISTS archive_settings (
    id                 INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled            BOOLEAN NOT NULL DEFAULT FALSE,
    backend            TEXT NOT NULL DEFAULT 'nfs'
                       CHECK (backend IN ('nfs', 'smb')),
    age_days           INT NOT NULL DEFAULT 7,
    interval_minutes   INT NOT NULL DEFAULT 60,
    delete_local       BOOLEAN NOT NULL DEFAULT FALSE,
    nfs_path           TEXT NOT NULL DEFAULT '',
    smb_host           TEXT NOT NULL DEFAULT '',
    smb_share          TEXT NOT NULL DEFAULT '',
    smb_user           TEXT NOT NULL DEFAULT '',
    smb_domain         TEXT NOT NULL DEFAULT '',
    smb_password_enc   BYTEA,
    last_run_at        TIMESTAMPTZ,
    last_error         TEXT NOT NULL DEFAULT '',
    last_copied        INT NOT NULL DEFAULT 0,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by         UUID REFERENCES users(id)
);

INSERT INTO archive_settings (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS archived BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS archive_sha256 TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS archive_backend TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_sessions_archive_pending
    ON sessions (ended_at)
    WHERE archived = FALSE AND recording_path <> '' AND status IN ('ended', 'failed');

-- +goose Down

DROP INDEX IF EXISTS idx_sessions_archive_pending;
ALTER TABLE sessions
    DROP COLUMN IF EXISTS archived,
    DROP COLUMN IF EXISTS archive_sha256,
    DROP COLUMN IF EXISTS archive_backend,
    DROP COLUMN IF EXISTS archived_at;
DROP TABLE IF EXISTS archive_settings;
