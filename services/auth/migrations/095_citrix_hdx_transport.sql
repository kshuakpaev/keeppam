-- +goose Up
-- SOW-CITRIX-HDX phase 3: allow citrix_transport=hdx (OEM plugin terminate).

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_citrix_transport_check;
ALTER TABLE assets ADD CONSTRAINT assets_citrix_transport_check
    CHECK (citrix_transport IN ('socks', 'hdx_pending', 'hdx'));

COMMENT ON COLUMN assets.citrix_transport IS 'socks=MVP SOCKS; hdx_pending=await OEM; hdx=OEM plugin terminate';

-- +goose Down
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_citrix_transport_check;
ALTER TABLE assets ADD CONSTRAINT assets_citrix_transport_check
    CHECK (citrix_transport IN ('socks', 'hdx_pending'));
