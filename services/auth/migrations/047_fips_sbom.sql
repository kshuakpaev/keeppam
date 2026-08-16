-- +goose Up

UPDATE compliance_packs
SET controls = controls || '["fips_crypto"]'::jsonb
WHERE id IN ('sox-lite', 'pci-lite')
  AND NOT (controls @> '"fips_crypto"'::jsonb);

UPDATE compliance_packs
SET controls = controls || '["sbom"]'::jsonb
WHERE id IN ('baseline', 'sox-lite', 'pci-lite')
  AND NOT (controls @> '"sbom"'::jsonb);

-- +goose Down
UPDATE compliance_packs
SET controls = (
  SELECT COALESCE(jsonb_agg(value), '[]'::jsonb)
  FROM jsonb_array_elements(controls) AS t(value)
  WHERE value::text NOT IN ('"fips_crypto"', '"sbom"')
);
