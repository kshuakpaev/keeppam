-- +goose Up
-- SOW-RADIUS-EAP: EAP-TTLS / PEAP and optional RadSec transport.

ALTER TABLE auth_settings
    ADD COLUMN IF NOT EXISTS radius_auth_method TEXT NOT NULL DEFAULT 'pap'
        CHECK (radius_auth_method IN ('pap', 'eap-ttls', 'peap')),
    ADD COLUMN IF NOT EXISTS radius_eap_ca_pem TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS radius_eap_anonymous_user TEXT NOT NULL DEFAULT 'anonymous',
    ADD COLUMN IF NOT EXISTS radius_eap_insecure_tls BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS radius_radsec BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS radius_radsec_ca_pem TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS radius_radsec_client_pem TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN auth_settings.radius_auth_method IS 'pap | eap-ttls (inner PAP) | peap (MSCHAPv2)';
COMMENT ON COLUMN auth_settings.radius_eap_ca_pem IS 'CA PEM to validate EAP tunnel server cert';
COMMENT ON COLUMN auth_settings.radius_radsec IS 'Use RADIUS/TLS (RadSec) instead of UDP';

-- +goose Down
ALTER TABLE auth_settings
    DROP COLUMN IF EXISTS radius_radsec_client_pem,
    DROP COLUMN IF EXISTS radius_radsec_ca_pem,
    DROP COLUMN IF EXISTS radius_radsec,
    DROP COLUMN IF EXISTS radius_eap_insecure_tls,
    DROP COLUMN IF EXISTS radius_eap_anonymous_user,
    DROP COLUMN IF EXISTS radius_eap_ca_pem,
    DROP COLUMN IF EXISTS radius_auth_method;
