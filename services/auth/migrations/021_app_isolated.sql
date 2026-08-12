-- +goose Up

ALTER TABLE app_integrations DROP CONSTRAINT IF EXISTS app_integrations_recording_mode_check;
ALTER TABLE app_integrations ADD CONSTRAINT app_integrations_recording_mode_check
    CHECK (recording_mode IN ('off', 'full', 'isolated'));

-- +goose Down
ALTER TABLE app_integrations DROP CONSTRAINT IF EXISTS app_integrations_recording_mode_check;
ALTER TABLE app_integrations ADD CONSTRAINT app_integrations_recording_mode_check
    CHECK (recording_mode IN ('off', 'full'));
