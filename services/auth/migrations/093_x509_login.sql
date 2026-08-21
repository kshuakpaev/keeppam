-- +goose Up
ALTER TABLE users ADD COLUMN IF NOT EXISTS x509_identity TEXT;

-- Explicit map: CN / email SAN / custom identity → user (case-insensitive unique).
CREATE UNIQUE INDEX IF NOT EXISTS users_x509_identity_uidx
    ON users (lower(x509_identity))
    WHERE x509_identity IS NOT NULL AND btrim(x509_identity) <> '';

COMMENT ON COLUMN users.x509_identity IS 'Client cert identity for login (CN or email SAN); empty = fallback username/email match';

-- +goose Down
DROP INDEX IF EXISTS users_x509_identity_uidx;
ALTER TABLE users DROP COLUMN IF EXISTS x509_identity;
