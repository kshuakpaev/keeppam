-- +goose Up

CREATE TABLE IF NOT EXISTS ai_settings (
    id               INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    mode             TEXT NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'on', 'external')),
    endpoint         TEXT NOT NULL DEFAULT 'mock://local',
    model            TEXT NOT NULL DEFAULT 'mock',
    embed_model      TEXT NOT NULL DEFAULT 'mock',
    max_input_chars  INT NOT NULL DEFAULT 48000 CHECK (max_input_chars BETWEEN 4000 AND 200000),
    timeout_s        INT NOT NULL DEFAULT 90 CHECK (timeout_s BETWEEN 15 AND 300),
    lang             TEXT NOT NULL DEFAULT 'ru' CHECK (lang IN ('ru', 'en', 'session')),
    last_run_at      TIMESTAMPTZ,
    last_error       TEXT NOT NULL DEFAULT '',
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO ai_settings (id) VALUES (1) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS ai_jobs (
    id          UUID PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN (
        'session_summary', 'embed_session', 'approval_brief', 'risk_explain',
        'compliance_prose', 'help_ask', 'jea_draft'
    )),
    ref_id      UUID NOT NULL,
    status      TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'error', 'skipped')),
    attempts    INT NOT NULL DEFAULT 0,
    error       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_jobs_active
    ON ai_jobs (kind, ref_id) WHERE status IN ('queued', 'running');

CREATE INDEX IF NOT EXISTS idx_ai_jobs_queue ON ai_jobs (status, created_at) WHERE status = 'queued';

CREATE TABLE IF NOT EXISTS session_ai_summaries (
    session_id        UUID PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'ready', 'error', 'skipped')),
    model             TEXT NOT NULL DEFAULT '',
    headline          TEXT NOT NULL DEFAULT '',
    summary           TEXT NOT NULL DEFAULT '',
    screen_narrative  TEXT NOT NULL DEFAULT '',
    bullets           JSONB NOT NULL DEFAULT '[]'::jsonb,
    risk_notes        JSONB NOT NULL DEFAULT '[]'::jsonb,
    offsets           JSONB NOT NULL DEFAULT '[]'::jsonb,
    input_hash        TEXT NOT NULL DEFAULT '',
    skip_reason       TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS session_event_embeddings (
    event_id    UUID PRIMARY KEY,
    session_id  UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    embedding   JSONB NOT NULL DEFAULT '[]'::jsonb,
    model       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_session_event_embeddings_session
    ON session_event_embeddings (session_id);

CREATE TABLE IF NOT EXISTS session_ai_risk (
    session_id  UUID PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    status      TEXT NOT NULL DEFAULT 'pending',
    model       TEXT NOT NULL DEFAULT '',
    text        TEXT NOT NULL DEFAULT '',
    factors     JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ai_briefs (
    kind        TEXT NOT NULL,
    ref_id      UUID NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    model       TEXT NOT NULL DEFAULT '',
    facts       JSONB NOT NULL DEFAULT '{}'::jsonb,
    brief       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (kind, ref_id)
);

-- +goose Down

DROP TABLE IF EXISTS ai_briefs;
DROP TABLE IF EXISTS session_ai_risk;
DROP TABLE IF EXISTS session_event_embeddings;
DROP TABLE IF EXISTS session_ai_summaries;
DROP TABLE IF EXISTS ai_jobs;
DROP TABLE IF EXISTS ai_settings;
