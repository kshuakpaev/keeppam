-- +goose Up

CREATE TABLE http_policy_packs (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    mode        TEXT NOT NULL DEFAULT 'allowlist'
                CHECK (mode IN ('allowlist', 'denylist')),
    -- rules: "METHOD PATH", METHOD=*|GET|POST|…, PATH glob (* matches /)
    rules       TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS http_policy_pack_id UUID REFERENCES http_policy_packs(id) ON DELETE SET NULL;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS http_policy_pack_id UUID REFERENCES http_policy_packs(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_acl_http_pack ON asset_access_bindings (http_policy_pack_id)
    WHERE http_policy_pack_id IS NOT NULL;

INSERT INTO http_policy_packs (id, name, description, mode, rules) VALUES
('01900000-0000-7000-8000-000000000072', 'http-readonly',
 'Только чтение: GET/HEAD/OPTIONS на любой путь', 'allowlist',
 ARRAY['GET *', 'HEAD *', 'OPTIONS *']),
('01900000-0000-7000-8000-000000000073', 'http-block-admin',
 'Запрет /admin* и любых DELETE', 'denylist',
 ARRAY['* /admin*', 'DELETE *']);

-- +goose Down
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS http_policy_pack_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS http_policy_pack_id;
DROP TABLE IF EXISTS http_policy_packs;
