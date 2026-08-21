-- +goose Up

-- In-flight remote rotation checkpoint (HA / crash recovery).
CREATE TABLE IF NOT EXISTS secret_rotation_pending (
    id              UUID PRIMARY KEY,
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    account_id      UUID NOT NULL REFERENCES asset_accounts(id) ON DELETE CASCADE,
    method          TEXT NOT NULL,
    old_secret_enc  BYTEA NOT NULL,
    new_secret_enc  BYTEA NOT NULL,
    remote_applied  BOOLEAN NOT NULL DEFAULT FALSE,
    actor_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS secret_rotation_pending_account_uidx
    ON secret_rotation_pending (account_id);

CREATE INDEX IF NOT EXISTS secret_rotation_pending_updated_idx
    ON secret_rotation_pending (updated_at);

ALTER TABLE secret_rotations
    DROP CONSTRAINT IF EXISTS secret_rotations_status_check;

ALTER TABLE secret_rotations
    ADD CONSTRAINT secret_rotations_status_check
    CHECK (status IN ('success', 'failed', 'reconciled'));

-- +goose Down
ALTER TABLE secret_rotations DROP CONSTRAINT IF EXISTS secret_rotations_status_check;
ALTER TABLE secret_rotations
    ADD CONSTRAINT secret_rotations_status_check
    CHECK (status IN ('success', 'failed'));
DROP TABLE IF EXISTS secret_rotation_pending;
