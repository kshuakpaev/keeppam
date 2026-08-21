-- +goose Up

-- T-43: SSH/Telnet terminal charset for transcript index (UTF-8 search).
ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS terminal_charset TEXT NOT NULL DEFAULT 'utf-8';

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_terminal_charset_check;
ALTER TABLE assets
    ADD CONSTRAINT assets_terminal_charset_check
    CHECK (terminal_charset IN ('utf-8', 'cp1251', 'koi8-r', 'auto'));

-- +goose Down

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_terminal_charset_check;
ALTER TABLE assets DROP COLUMN IF EXISTS terminal_charset;
