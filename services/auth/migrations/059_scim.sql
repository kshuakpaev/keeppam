-- +goose Up

-- Inbound SCIM 2.0 (KeepPAM = service provider). Token is envelope-encrypted.

ALTER TABLE auth_settings
    ADD COLUMN IF NOT EXISTS scim_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS scim_token_enc BYTEA,
    ADD COLUMN IF NOT EXISTS scim_default_role TEXT NOT NULL DEFAULT 'operator';

CREATE TABLE IF NOT EXISTS scim_aliases (
    kind        TEXT NOT NULL CHECK (kind IN ('user', 'group')),
    keeppam_id  UUID NOT NULL,
    external_id TEXT NOT NULL,
    PRIMARY KEY (kind, keeppam_id),
    UNIQUE (kind, external_id)
);

-- +goose Down

DROP TABLE IF EXISTS scim_aliases;
ALTER TABLE auth_settings DROP COLUMN IF EXISTS scim_default_role;
ALTER TABLE auth_settings DROP COLUMN IF EXISTS scim_token_enc;
ALTER TABLE auth_settings DROP COLUMN IF EXISTS scim_enabled;
