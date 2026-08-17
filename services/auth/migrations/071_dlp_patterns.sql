-- +goose Up

CREATE TABLE IF NOT EXISTS dlp_patterns (
    id UUID PRIMARY KEY,
    access_policy_id UUID NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    pattern TEXT NOT NULL,
    sort_order INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT dlp_patterns_name_chk CHECK (name ~ '^[a-z][a-z0-9_]{0,31}$'),
    CONSTRAINT dlp_patterns_pattern_len CHECK (char_length(pattern) BETWEEN 1 AND 512),
    UNIQUE (access_policy_id, name)
);

CREATE INDEX IF NOT EXISTS idx_dlp_patterns_policy ON dlp_patterns(access_policy_id, sort_order);

-- +goose Down

DROP TABLE IF EXISTS dlp_patterns;
