-- +goose Up
-- SOW-TN3270-DBCS: DBCS terminal profile + EBCDIC codepage per TN3270 asset.

ALTER TABLE assets ADD COLUMN IF NOT EXISTS tn3270_codepage TEXT NOT NULL DEFAULT 'cp037'
    CHECK (tn3270_codepage IN ('cp037', 'cp930', 'cp939', 'cp933'));

ALTER TABLE assets ADD COLUMN IF NOT EXISTS tn3270_terminal_type TEXT NOT NULL DEFAULT '';

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_tn3270_terminal_type_check;
ALTER TABLE assets ADD CONSTRAINT assets_tn3270_terminal_type_check
    CHECK (tn3270_terminal_type IN ('', 'IBM-3278-2', 'IBM-3278-4', 'IBM-3279-4', 'IBM-3278-5'));

COMMENT ON COLUMN assets.tn3270_codepage IS 'EBCDIC codepage for forensic decode: cp037 Latin, cp930/cp939 JP, cp933 KR';
COMMENT ON COLUMN assets.tn3270_terminal_type IS 'TN3270 TERMINAL-TYPE override; empty = auto from codepage';

-- +goose Down
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_tn3270_terminal_type_check;
ALTER TABLE assets DROP COLUMN IF EXISTS tn3270_terminal_type;
ALTER TABLE assets DROP COLUMN IF EXISTS tn3270_codepage;
