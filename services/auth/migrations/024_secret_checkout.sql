-- +goose Up

ALTER TABLE asset_accounts
    ADD COLUMN IF NOT EXISTS checkout_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS checkout_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS checkout_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS checkout_reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS rotate_after_session BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS rotate_on_checkin BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS rotate_interval_hours INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS next_rotate_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS dual_control_checkout BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE asset_accounts
    DROP CONSTRAINT IF EXISTS asset_accounts_rotate_interval_hours_check;
ALTER TABLE asset_accounts
    ADD CONSTRAINT asset_accounts_rotate_interval_hours_check CHECK (rotate_interval_hours >= 0);

CREATE TABLE IF NOT EXISTS secret_checkout_requests (
    id            UUID PRIMARY KEY,
    asset_id      UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    account_id    UUID NOT NULL REFERENCES asset_accounts(id) ON DELETE CASCADE,
    requester_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason        TEXT NOT NULL DEFAULT '',
    ttl_minutes   INT NOT NULL DEFAULT 60,
    status        TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'cancelled', 'expired')),
    approver_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    decided_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS secret_checkout_requests_pending_idx
    ON secret_checkout_requests (status, created_at DESC);
CREATE INDEX IF NOT EXISTS secret_checkout_requests_account_idx
    ON secret_checkout_requests (account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS secret_checkout_events (
    id          UUID PRIMARY KEY,
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    account_id  UUID NOT NULL REFERENCES asset_accounts(id) ON DELETE CASCADE,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type  TEXT NOT NULL,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS secret_checkout_events_account_idx
    ON secret_checkout_events (account_id, created_at DESC);

CREATE INDEX IF NOT EXISTS asset_accounts_next_rotate_idx
    ON asset_accounts (next_rotate_at)
    WHERE next_rotate_at IS NOT NULL AND status = 'active';

CREATE INDEX IF NOT EXISTS asset_accounts_checkout_exp_idx
    ON asset_accounts (checkout_expires_at)
    WHERE checkout_user_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS asset_accounts_checkout_exp_idx;
DROP INDEX IF EXISTS asset_accounts_next_rotate_idx;
DROP TABLE IF EXISTS secret_checkout_events;
DROP TABLE IF EXISTS secret_checkout_requests;
ALTER TABLE asset_accounts
    DROP CONSTRAINT IF EXISTS asset_accounts_rotate_interval_hours_check;
ALTER TABLE asset_accounts
    DROP COLUMN IF EXISTS checkout_user_id,
    DROP COLUMN IF EXISTS checkout_at,
    DROP COLUMN IF EXISTS checkout_expires_at,
    DROP COLUMN IF EXISTS checkout_reason,
    DROP COLUMN IF EXISTS rotate_after_session,
    DROP COLUMN IF EXISTS rotate_on_checkin,
    DROP COLUMN IF EXISTS rotate_interval_hours,
    DROP COLUMN IF EXISTS next_rotate_at,
    DROP COLUMN IF EXISTS dual_control_checkout;
