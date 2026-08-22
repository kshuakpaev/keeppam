-- +goose Up
-- SOW-CITRIX-HDX slice 1: Citrix asset metadata (published app / StoreFront / STA URLs).
-- Full HDX terminate + screen recording remain OEM phases (docs/citrix-hdx.txt).

ALTER TABLE assets ADD COLUMN IF NOT EXISTS citrix_published_app TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS citrix_storefront_url TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS citrix_sta_urls TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS citrix_transport TEXT NOT NULL DEFAULT 'socks'
    CHECK (citrix_transport IN ('socks', 'hdx_pending'));

COMMENT ON COLUMN assets.citrix_published_app IS 'Published app / InitialProgram (e.g. #Excel or path)';
COMMENT ON COLUMN assets.citrix_storefront_url IS 'StoreFront base URL for future broker; informational in slice 1';
COMMENT ON COLUMN assets.citrix_sta_urls IS 'Comma-separated STA URLs (KeepPAM stub or real STA)';
COMMENT ON COLUMN assets.citrix_transport IS 'socks=MVP SOCKS; hdx_pending=await OEM HDX terminate';

-- +goose Down
ALTER TABLE assets DROP COLUMN IF EXISTS citrix_transport;
ALTER TABLE assets DROP COLUMN IF EXISTS citrix_sta_urls;
ALTER TABLE assets DROP COLUMN IF EXISTS citrix_storefront_url;
ALTER TABLE assets DROP COLUMN IF EXISTS citrix_published_app;
