-- +goose Up
-- NIT §9: risk_action terminate (kill session) and lock_account (24h lockout).

DO $$
DECLARE c text;
BEGIN
  SELECT conname INTO c FROM pg_constraint
   WHERE conrelid = 'asset_access_bindings'::regclass AND contype = 'c'
     AND pg_get_constraintdef(oid) LIKE '%risk_action%';
  IF c IS NOT NULL THEN
    EXECUTE format('ALTER TABLE asset_access_bindings DROP CONSTRAINT %I', c);
  END IF;
END $$;

ALTER TABLE asset_access_bindings
    ADD CONSTRAINT asset_access_bindings_risk_action_check
    CHECK (risk_action IN ('deny', 'require_approval', 'require_mfa', 'terminate', 'lock_account'));

DO $$
DECLARE c text;
BEGIN
  SELECT conname INTO c FROM pg_constraint
   WHERE conrelid = 'access_policies'::regclass AND contype = 'c'
     AND pg_get_constraintdef(oid) LIKE '%risk_action%';
  IF c IS NOT NULL THEN
    EXECUTE format('ALTER TABLE access_policies DROP CONSTRAINT %I', c);
  END IF;
END $$;

ALTER TABLE access_policies
    ADD CONSTRAINT access_policies_risk_action_check
    CHECK (risk_action IN ('deny', 'require_approval', 'require_mfa', 'terminate', 'lock_account'));

-- +goose Down

ALTER TABLE asset_access_bindings DROP CONSTRAINT IF EXISTS asset_access_bindings_risk_action_check;
ALTER TABLE asset_access_bindings
    ADD CONSTRAINT asset_access_bindings_risk_action_check
    CHECK (risk_action IN ('deny', 'require_approval', 'require_mfa'));

ALTER TABLE access_policies DROP CONSTRAINT IF EXISTS access_policies_risk_action_check;
ALTER TABLE access_policies
    ADD CONSTRAINT access_policies_risk_action_check
    CHECK (risk_action IN ('deny', 'require_approval', 'require_mfa'));
