-- +goose Up

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS pam_only BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE IF NOT EXISTS firewall_settings (
    id                 INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    pam_gateway_cidrs  TEXT[] NOT NULL DEFAULT '{}',
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO firewall_settings (id) VALUES (1) ON CONFLICT DO NOTHING;

-- +goose Down

DROP TABLE IF EXISTS firewall_settings;
ALTER TABLE assets DROP COLUMN IF EXISTS pam_only;
