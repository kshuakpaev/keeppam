-- +goose Up

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS ad_privileged_group_dn TEXT NOT NULL DEFAULT '';

ALTER TABLE asset_accounts
    ADD COLUMN IF NOT EXISTS ad_user_dn TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS session_ad_memberships (
    session_id   UUID PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    asset_id     UUID NOT NULL REFERENCES assets(id),
    account_id   UUID NOT NULL REFERENCES asset_accounts(id),
    group_dn     TEXT NOT NULL,
    user_dn      TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'joined', 'left', 'failed_join', 'failed_leave')),
    joined_at    TIMESTAMPTZ,
    left_at      TIMESTAMPTZ,
    last_error   TEXT NOT NULL DEFAULT '',
    rotate_done  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_session_ad_memberships_status
    ON session_ad_memberships (status) WHERE status IN ('joined', 'failed_leave');

-- +goose Down
DROP TABLE IF EXISTS session_ad_memberships;
ALTER TABLE asset_accounts DROP COLUMN IF EXISTS ad_user_dn;
ALTER TABLE assets DROP COLUMN IF EXISTS ad_privileged_group_dn;
