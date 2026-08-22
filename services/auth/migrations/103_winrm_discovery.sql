-- +goose Up

ALTER TABLE discovery_jobs DROP CONSTRAINT IF EXISTS discovery_jobs_kind_check;
ALTER TABLE discovery_jobs
    ADD CONSTRAINT discovery_jobs_kind_check
    CHECK (kind IN ('network', 'accounts', 'ad_accounts', 'winrm_accounts'));

-- +goose Down

ALTER TABLE discovery_jobs DROP CONSTRAINT IF EXISTS discovery_jobs_kind_check;
ALTER TABLE discovery_jobs
    ADD CONSTRAINT discovery_jobs_kind_check
    CHECK (kind IN ('network', 'accounts', 'ad_accounts'));
