-- +goose Up

ALTER TABLE access_policies
    ADD COLUMN IF NOT EXISTS ocr_lang TEXT NOT NULL DEFAULT 'rus+eng',
    ADD COLUMN IF NOT EXISTS ocr_interval_sec INT NOT NULL DEFAULT 15,
    ADD COLUMN IF NOT EXISTS ocr_max_frames INT NOT NULL DEFAULT 60;

ALTER TABLE access_policies DROP CONSTRAINT IF EXISTS access_policies_ocr_interval_check;
ALTER TABLE access_policies
    ADD CONSTRAINT access_policies_ocr_interval_check
    CHECK (ocr_interval_sec BETWEEN 5 AND 120);

ALTER TABLE access_policies DROP CONSTRAINT IF EXISTS access_policies_ocr_frames_check;
ALTER TABLE access_policies
    ADD CONSTRAINT access_policies_ocr_frames_check
    CHECK (ocr_max_frames BETWEEN 1 AND 120);

-- +goose Down

ALTER TABLE access_policies DROP CONSTRAINT IF EXISTS access_policies_ocr_interval_check;
ALTER TABLE access_policies DROP CONSTRAINT IF EXISTS access_policies_ocr_frames_check;
ALTER TABLE access_policies DROP COLUMN IF EXISTS ocr_lang;
ALTER TABLE access_policies DROP COLUMN IF EXISTS ocr_interval_sec;
ALTER TABLE access_policies DROP COLUMN IF EXISTS ocr_max_frames;
