-- +goose Up

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS policy_snapshot JSONB;

COMMENT ON COLUMN sessions.policy_snapshot IS 'Frozen ACL/Policy at connect (max_risk, packs, binding). In-session ops use this, not live Policy.';

-- +goose Down
ALTER TABLE sessions DROP COLUMN IF EXISTS policy_snapshot;
