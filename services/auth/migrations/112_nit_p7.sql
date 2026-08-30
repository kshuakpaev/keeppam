-- +goose Up
-- NIT §7: hot video 30 days on local disks, then archive to NFS/SMB (CIFS v2–3) / S3 hybrid.

ALTER TABLE archive_settings ALTER COLUMN age_days SET DEFAULT 30;
UPDATE archive_settings SET age_days = 30 WHERE id = 1 AND age_days = 7;

COMMENT ON COLUMN archive_settings.age_days IS 'Days recordings stay on local disks before archive (NIT hot tier: 30)';

-- +goose Down
ALTER TABLE archive_settings ALTER COLUMN age_days SET DEFAULT 7;
