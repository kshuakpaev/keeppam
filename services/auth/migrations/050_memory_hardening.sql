-- +goose Up

UPDATE compliance_packs
SET controls = controls || '["memory_hardening"]'::jsonb
WHERE id IN ('baseline', 'sox-lite', 'pci-lite')
  AND NOT (controls @> '"memory_hardening"'::jsonb);

-- +goose Down
UPDATE compliance_packs
SET controls = (
  SELECT COALESCE(jsonb_agg(value), '[]'::jsonb)
  FROM jsonb_array_elements(controls) AS t(value)
  WHERE value::text <> '"memory_hardening"'
);
