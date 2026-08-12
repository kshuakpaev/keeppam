-- +goose Up

CREATE TABLE sql_policy_packs (
    id               UUID PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    description      TEXT NOT NULL DEFAULT '',
    mode             TEXT NOT NULL DEFAULT 'allowlist'
                     CHECK (mode IN ('allowlist', 'denylist')),
    -- statement verbs: SELECT, INSERT, UPDATE, DELETE, DDL, OTHER (empty = any)
    statements       TEXT[] NOT NULL DEFAULT '{}',
    -- table globs: tickets, public.tickets, * (empty allowlist = deny all tables when mode=allowlist)
    tables           TEXT[] NOT NULL DEFAULT '{}',
    -- column names (or table.column) to mask in result sets
    mask_columns     TEXT[] NOT NULL DEFAULT '{}',
    mask_replacement TEXT NOT NULL DEFAULT '***',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS sql_policy_pack_id UUID REFERENCES sql_policy_packs(id) ON DELETE SET NULL;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS sql_policy_pack_id UUID REFERENCES sql_policy_packs(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_acl_sql_pack ON asset_access_bindings (sql_policy_pack_id)
    WHERE sql_policy_pack_id IS NOT NULL;

INSERT INTO sql_policy_packs (id, name, description, mode, statements, tables, mask_columns, mask_replacement) VALUES
('01900000-0000-7000-8000-000000000070', 'sql-readonly-tickets',
 'SELECT only on tickets*; mask amount', 'allowlist',
 ARRAY['SELECT'], ARRAY['tickets','tickets*','public.tickets'], ARRAY['amount'], '***'),
('01900000-0000-7000-8000-000000000071', 'sql-block-ddl',
 'Запрет DDL/DCL (DROP/ALTER/CREATE/TRUNCATE/GRANT)', 'denylist',
 ARRAY['DDL'], ARRAY['*'], ARRAY[]::TEXT[], '***');

-- +goose Down
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS sql_policy_pack_id;
DROP TABLE IF EXISTS sql_policy_packs;
