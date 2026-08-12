-- +goose Up

UPDATE compliance_packs
SET controls = controls || '["worm_recordings","kms_hsm_key"]'::jsonb
WHERE id IN ('sox-lite', 'pci-lite')
  AND NOT (controls @> '"worm_recordings"'::jsonb);

UPDATE compliance_packs
SET controls = controls || '["worm_recordings"]'::jsonb
WHERE id = 'baseline'
  AND NOT (controls @> '"worm_recordings"'::jsonb);

-- +goose Down
UPDATE compliance_packs
SET controls = (
  SELECT COALESCE(jsonb_agg(value), '[]'::jsonb)
  FROM jsonb_array_elements(controls) AS t(value)
  WHERE value::text NOT IN ('"worm_recordings"', '"kms_hsm_key"')
);
