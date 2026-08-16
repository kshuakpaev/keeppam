-- +goose Up

-- risk_action: deny | require_approval | require_mfa (step-up TOTP/WebAuthn on connect)

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
    CHECK (risk_action IN ('deny', 'require_approval', 'require_mfa'));

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
    CHECK (risk_action IN ('deny', 'require_approval', 'require_mfa'));

INSERT INTO access_policies (id, name, description, max_risk, risk_action) VALUES
('01900000-0000-7000-8000-000000000083', 'adaptive-mfa',
 'Порог риска 40: выше — повторный MFA на connect (не JIT)',
 40, 'require_mfa')
ON CONFLICT (name) DO NOTHING;

-- +goose Down

DELETE FROM access_policies WHERE id = '01900000-0000-7000-8000-000000000083';

ALTER TABLE asset_access_bindings DROP CONSTRAINT IF EXISTS asset_access_bindings_risk_action_check;
ALTER TABLE asset_access_bindings
    ADD CONSTRAINT asset_access_bindings_risk_action_check
    CHECK (risk_action IN ('deny', 'require_approval'));

ALTER TABLE access_policies DROP CONSTRAINT IF EXISTS access_policies_risk_action_check;
ALTER TABLE access_policies
    ADD CONSTRAINT access_policies_risk_action_check
    CHECK (risk_action IN ('deny', 'require_approval'));
