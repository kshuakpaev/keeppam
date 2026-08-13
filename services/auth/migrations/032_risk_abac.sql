-- +goose Up

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS max_risk INT NOT NULL DEFAULT 0
        CHECK (max_risk BETWEEN 0 AND 100),
    ADD COLUMN IF NOT EXISTS risk_action TEXT NOT NULL DEFAULT 'deny'
        CHECK (risk_action IN ('deny', 'require_approval'));

ALTER TABLE access_requests
    ADD COLUMN IF NOT EXISTS risk_score INT,
    ADD COLUMN IF NOT EXISTS risk_factors TEXT[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE access_requests DROP COLUMN IF EXISTS risk_factors;
ALTER TABLE access_requests DROP COLUMN IF EXISTS risk_score;
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS risk_action;
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS max_risk;
