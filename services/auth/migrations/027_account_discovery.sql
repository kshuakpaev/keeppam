-- +goose Up

ALTER TABLE discovery_jobs
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'network';

ALTER TABLE discovery_jobs
    DROP CONSTRAINT IF EXISTS discovery_jobs_kind_check;
ALTER TABLE discovery_jobs
    ADD CONSTRAINT discovery_jobs_kind_check CHECK (kind IN ('network', 'accounts'));

ALTER TABLE discovery_candidates
    ADD COLUMN IF NOT EXISTS username TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS imported_account_id UUID REFERENCES asset_accounts(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS details JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS privileged BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE discovery_candidates
    DROP CONSTRAINT IF EXISTS discovery_candidates_job_id_address_port_key;

CREATE UNIQUE INDEX IF NOT EXISTS discovery_candidates_uniq
    ON discovery_candidates (job_id, address, port, username);

CREATE INDEX IF NOT EXISTS discovery_candidates_source_asset_idx
    ON discovery_candidates (source_asset_id)
    WHERE source_asset_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS discovery_candidates_source_asset_idx;
DROP INDEX IF EXISTS discovery_candidates_uniq;
ALTER TABLE discovery_candidates
    DROP COLUMN IF EXISTS privileged,
    DROP COLUMN IF EXISTS details,
    DROP COLUMN IF EXISTS imported_account_id,
    DROP COLUMN IF EXISTS source_asset_id,
    DROP COLUMN IF EXISTS username;
ALTER TABLE discovery_jobs DROP CONSTRAINT IF EXISTS discovery_jobs_kind_check;
ALTER TABLE discovery_jobs DROP COLUMN IF EXISTS kind;
