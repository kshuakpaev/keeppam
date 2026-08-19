-- +goose Up

-- JIT quorum N-of-M (main22 T-16). Sequential manager→security stays default.

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS approval_mode TEXT NOT NULL DEFAULT 'sequential',
    ADD COLUMN IF NOT EXISTS quorum_n INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS quorum_m INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS approver_group_id UUID REFERENCES groups(id) ON DELETE SET NULL;

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_approval_mode_check;
ALTER TABLE assets
    ADD CONSTRAINT assets_approval_mode_check
    CHECK (approval_mode IN ('sequential', 'quorum'));

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_quorum_nm_check;
ALTER TABLE assets
    ADD CONSTRAINT assets_quorum_nm_check
    CHECK (quorum_n >= 1 AND quorum_n <= 16 AND quorum_m >= 1 AND quorum_m <= 16 AND quorum_n <= quorum_m);

CREATE INDEX IF NOT EXISTS idx_assets_approver_group ON assets (approver_group_id)
    WHERE approver_group_id IS NOT NULL;

ALTER TABLE access_requests
    ADD COLUMN IF NOT EXISTS approval_mode TEXT NOT NULL DEFAULT 'sequential',
    ADD COLUMN IF NOT EXISTS quorum_n INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS quorum_m INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS approver_group_id UUID REFERENCES groups(id) ON DELETE SET NULL;

ALTER TABLE access_requests DROP CONSTRAINT IF EXISTS access_requests_approval_mode_check;
ALTER TABLE access_requests
    ADD CONSTRAINT access_requests_approval_mode_check
    CHECK (approval_mode IN ('sequential', 'quorum'));

ALTER TABLE access_requests DROP CONSTRAINT IF EXISTS access_requests_quorum_nm_check;
ALTER TABLE access_requests
    ADD CONSTRAINT access_requests_quorum_nm_check
    CHECK (quorum_n >= 1 AND quorum_n <= 16 AND quorum_m >= 1 AND quorum_m <= 16 AND quorum_n <= quorum_m);

-- Multiple votes share stage 'quorum'; one vote per actor. Sequential still unique per stage.
DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'access_request_approvals'::regclass AND contype = 'u'
  LOOP
    EXECUTE format('ALTER TABLE access_request_approvals DROP CONSTRAINT IF EXISTS %I', r.conname);
  END LOOP;
END $$;

ALTER TABLE access_request_approvals DROP CONSTRAINT IF EXISTS access_request_approvals_stage_check;
ALTER TABLE access_request_approvals
    ADD CONSTRAINT access_request_approvals_stage_check
    CHECK (stage IN ('manager', 'security', 'quorum'));

CREATE UNIQUE INDEX IF NOT EXISTS idx_access_request_approvals_actor
    ON access_request_approvals (request_id, actor_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_access_request_approvals_seq_stage
    ON access_request_approvals (request_id, stage)
    WHERE stage IN ('manager', 'security');

-- +goose Down

DROP INDEX IF EXISTS idx_access_request_approvals_seq_stage;
DROP INDEX IF EXISTS idx_access_request_approvals_actor;

ALTER TABLE access_request_approvals DROP CONSTRAINT IF EXISTS access_request_approvals_stage_check;
ALTER TABLE access_request_approvals
    ADD CONSTRAINT access_request_approvals_stage_check
    CHECK (stage IN ('manager', 'security'));

CREATE UNIQUE INDEX IF NOT EXISTS access_request_approvals_request_id_stage_key
    ON access_request_approvals (request_id, stage);

ALTER TABLE access_requests DROP CONSTRAINT IF EXISTS access_requests_quorum_nm_check;
ALTER TABLE access_requests DROP CONSTRAINT IF EXISTS access_requests_approval_mode_check;
ALTER TABLE access_requests DROP COLUMN IF EXISTS approver_group_id;
ALTER TABLE access_requests DROP COLUMN IF EXISTS quorum_m;
ALTER TABLE access_requests DROP COLUMN IF EXISTS quorum_n;
ALTER TABLE access_requests DROP COLUMN IF EXISTS approval_mode;

DROP INDEX IF EXISTS idx_assets_approver_group;
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_quorum_nm_check;
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_approval_mode_check;
ALTER TABLE assets DROP COLUMN IF EXISTS approver_group_id;
ALTER TABLE assets DROP COLUMN IF EXISTS quorum_m;
ALTER TABLE assets DROP COLUMN IF EXISTS quorum_n;
ALTER TABLE assets DROP COLUMN IF EXISTS approval_mode;
