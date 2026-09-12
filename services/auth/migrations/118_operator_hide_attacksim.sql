-- +goose Up
-- Operator does not run or view Attack sim (admin control checks).

DELETE FROM role_permissions
WHERE role_id = '01900000-0000-7000-8000-000000000002'
  AND permission_id = '01900000-0000-7000-8000-000000000070';

-- +goose Down
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-000000000070')
ON CONFLICT DO NOTHING;
