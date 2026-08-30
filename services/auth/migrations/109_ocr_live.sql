-- +goose Up

ALTER TABLE access_policies
    ADD COLUMN IF NOT EXISTS ocr_every_frame BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS ocr_live BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS ocr_ssh_stdout BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE access_policies DROP CONSTRAINT IF EXISTS access_policies_ocr_frames_check;
ALTER TABLE access_policies
    ADD CONSTRAINT access_policies_ocr_frames_check
    CHECK (ocr_max_frames BETWEEN 1 AND 3600);

-- +goose Down

ALTER TABLE access_policies DROP CONSTRAINT IF EXISTS access_policies_ocr_frames_check;
ALTER TABLE access_policies
    ADD CONSTRAINT access_policies_ocr_frames_check
    CHECK (ocr_max_frames BETWEEN 1 AND 120);
ALTER TABLE access_policies DROP COLUMN IF EXISTS ocr_every_frame;
ALTER TABLE access_policies DROP COLUMN IF EXISTS ocr_live;
ALTER TABLE access_policies DROP COLUMN IF EXISTS ocr_ssh_stdout;
