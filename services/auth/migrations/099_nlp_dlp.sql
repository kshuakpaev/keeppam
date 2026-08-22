-- +goose Up

ALTER TABLE asset_access_bindings
    ADD COLUMN IF NOT EXISTS nlp_dlp_action TEXT NOT NULL DEFAULT ''
        CHECK (nlp_dlp_action IN ('', 'audit', 'mask', 'deny'));

ALTER TABLE access_policies
    ADD COLUMN IF NOT EXISTS nlp_dlp_action TEXT NOT NULL DEFAULT ''
        CHECK (nlp_dlp_action IN ('', 'audit', 'mask', 'deny'));

CREATE TABLE IF NOT EXISTS dlp_classifiers (
    id UUID PRIMARY KEY,
    access_policy_id UUID NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    keywords TEXT NOT NULL,
    min_hits INT NOT NULL DEFAULT 1,
    sort_order INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT dlp_classifiers_name_chk CHECK (name ~ '^[a-z][a-z0-9_]{0,31}$'),
    CONSTRAINT dlp_classifiers_keywords_len CHECK (char_length(keywords) BETWEEN 1 AND 4096),
    CONSTRAINT dlp_classifiers_min_hits_chk CHECK (min_hits BETWEEN 1 AND 8),
    UNIQUE (access_policy_id, name)
);

CREATE INDEX IF NOT EXISTS idx_dlp_classifiers_policy ON dlp_classifiers(access_policy_id, sort_order);

-- +goose Down

DROP TABLE IF EXISTS dlp_classifiers;
ALTER TABLE access_policies DROP COLUMN IF EXISTS nlp_dlp_action;
ALTER TABLE asset_access_bindings DROP COLUMN IF EXISTS nlp_dlp_action;
