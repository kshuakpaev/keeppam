-- +goose Up
-- Operator does not administer JEA packs / Access Policy (menu is jea.write).

DELETE FROM role_permissions
WHERE role_id = '01900000-0000-7000-8000-000000000002'
  AND permission_id = '01900000-0000-7000-8000-000000000062';

-- +goose Down
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-000000000062')
ON CONFLICT DO NOTHING;
