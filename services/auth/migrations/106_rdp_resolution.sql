-- +goose Up

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS rdp_width INT,
    ADD COLUMN IF NOT EXISTS rdp_height INT;

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_rdp_width_check;
ALTER TABLE sessions
    ADD CONSTRAINT sessions_rdp_width_check
    CHECK (rdp_width IS NULL OR (rdp_width >= 640 AND rdp_width <= 7680));

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_rdp_height_check;
ALTER TABLE sessions
    ADD CONSTRAINT sessions_rdp_height_check
    CHECK (rdp_height IS NULL OR (rdp_height >= 480 AND rdp_height <= 4320));

-- +goose Down

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_rdp_height_check;
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_rdp_width_check;
ALTER TABLE sessions DROP COLUMN IF EXISTS rdp_height;
ALTER TABLE sessions DROP COLUMN IF EXISTS rdp_width;
