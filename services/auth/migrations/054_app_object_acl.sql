-- +goose Up

CREATE TABLE app_object_packs (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    -- unmatched: allow = overlay (несовпавшее не режется); deny = allowlist функций
    unmatched   TEXT NOT NULL DEFAULT 'allow'
                CHECK (unmatched IN ('allow', 'deny')),
    -- rules: "METHOD PATH OBJECT ACTION"
    -- METHOD=*|GET|… PATH glob, OBJECT customer.view, ACTION=allow|deny|approval
    -- первое совпадение побеждает
    rules       TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS app_object_pack_id UUID REFERENCES app_object_packs(id) ON DELETE SET NULL;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS app_object_pack_id UUID REFERENCES app_object_packs(id) ON DELETE SET NULL;

ALTER TABLE access_policies
    ADD COLUMN IF NOT EXISTS app_object_pack_id UUID REFERENCES app_object_packs(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_acl_app_object_pack ON asset_access_bindings (app_object_pack_id)
    WHERE app_object_pack_id IS NOT NULL;

INSERT INTO app_object_packs (id, name, description, unmatched, rules) VALUES
('01900000-0000-7000-8000-000000000074', 'crm-objects',
 'CRM: просмотр/создание/правка клиента — allow; удаление — deny; экспорт — approval; admin — deny. Несовпавшее — deny.',
 'deny',
 ARRAY[
   'GET /api/customers/export customer.export approval',
   'GET /api/customers* customer.view allow',
   'POST /api/customers customer.create allow',
   'PUT /api/customers/* customer.update allow',
   'PATCH /api/customers/* customer.update allow',
   'DELETE /api/customers/* customer.delete deny',
   '* /admin* admin.panel deny'
 ]);

-- +goose Down
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS app_object_pack_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS app_object_pack_id;
ALTER TABLE access_policies DROP COLUMN IF EXISTS app_object_pack_id;
DROP TABLE IF EXISTS app_object_packs;
