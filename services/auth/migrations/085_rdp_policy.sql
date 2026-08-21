-- +goose Up

-- RDP redirection / native path (КП-2.6, T-27 / T-29). Default off = DLP-strict.
ALTER TABLE access_policies
    ADD COLUMN IF NOT EXISTS rdp_clipboard BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS rdp_drive BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS rdp_printer BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS rdp_native BOOLEAN NOT NULL DEFAULT false;

-- +goose Down

ALTER TABLE access_policies
    DROP COLUMN IF EXISTS rdp_clipboard,
    DROP COLUMN IF EXISTS rdp_drive,
    DROP COLUMN IF EXISTS rdp_printer,
    DROP COLUMN IF EXISTS rdp_native;
