-- +goose Up
-- NIT §5: native mstsc default when broker is deployed (DLP clip/drive/printer remain off).

ALTER TABLE access_policies ALTER COLUMN rdp_native SET DEFAULT true;

-- +goose Down
ALTER TABLE access_policies ALTER COLUMN rdp_native SET DEFAULT false;
