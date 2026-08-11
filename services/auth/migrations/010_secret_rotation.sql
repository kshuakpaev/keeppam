-- +goose Up

ALTER TABLE asset_accounts
    ADD COLUMN IF NOT EXISTS last_rotated_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS secret_rotations (
    id            UUID PRIMARY KEY,
    asset_id      UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    account_id    UUID NOT NULL REFERENCES asset_accounts(id) ON DELETE CASCADE,
    actor_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    method        TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('success', 'failed')),
    apply_remote  BOOLEAN NOT NULL DEFAULT TRUE,
    error         TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS secret_rotations_account_idx ON secret_rotations (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS secret_rotations_asset_idx ON secret_rotations (asset_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS secret_rotations;
ALTER TABLE asset_accounts DROP COLUMN IF EXISTS last_rotated_at;
