-- +goose Up
-- NIT §2: catalog indexes for large asset lists; data residency (KZ) attestation.

CREATE INDEX IF NOT EXISTS idx_assets_name_lower ON assets (lower(name));
CREATE INDEX IF NOT EXISTS idx_assets_hostname_lower ON assets (lower(hostname));
CREATE INDEX IF NOT EXISTS idx_assets_address ON assets (address);
CREATE INDEX IF NOT EXISTS idx_assets_status_name ON assets (status, name, id);

CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_assets_name_trgm ON assets USING gin (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_assets_hostname_trgm ON assets USING gin (hostname gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_assets_address_trgm ON assets USING gin (address gin_trgm_ops);

CREATE TABLE IF NOT EXISTS data_residency_settings (
    id            INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    region        TEXT NOT NULL DEFAULT 'KZ',
    country_name  TEXT NOT NULL DEFAULT 'Kazakhstan',
    on_prem       BOOLEAN NOT NULL DEFAULT TRUE,
    attested_at   TIMESTAMPTZ,
    attested_by   UUID REFERENCES users(id),
    notes         TEXT NOT NULL DEFAULT '',
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO data_residency_settings (id, region, country_name, on_prem)
VALUES (1, 'KZ', 'Kazakhstan', TRUE)
ON CONFLICT (id) DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS data_residency_settings;
DROP INDEX IF EXISTS idx_assets_address_trgm;
DROP INDEX IF EXISTS idx_assets_hostname_trgm;
DROP INDEX IF EXISTS idx_assets_name_trgm;
DROP INDEX IF EXISTS idx_assets_status_name;
DROP INDEX IF EXISTS idx_assets_address;
DROP INDEX IF EXISTS idx_assets_hostname_lower;
DROP INDEX IF EXISTS idx_assets_name_lower;
