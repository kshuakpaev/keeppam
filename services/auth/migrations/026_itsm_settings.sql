-- +goose Up

CREATE TABLE IF NOT EXISTS itsm_settings (
    id                     INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled                BOOLEAN NOT NULL DEFAULT FALSE,
    provider               TEXT NOT NULL DEFAULT 'mock'
                           CHECK (provider IN ('mock', 'generic', 'jira', 'servicenow')),
    base_url               TEXT NOT NULL DEFAULT '',
    auth_header_enc        BYTEA,
    ticket_path_template   TEXT NOT NULL DEFAULT '/rest/api/2/issue/{ticket}',
    status_json_path       TEXT NOT NULL DEFAULT 'fields.status.name',
    ok_statuses            TEXT[] NOT NULL DEFAULT ARRAY['Open','In Progress','To Do','New','Assigned','Work in Progress'],
    require_on_request     BOOLEAN NOT NULL DEFAULT FALSE,
    require_on_approve     BOOLEAN NOT NULL DEFAULT TRUE,
    require_on_connect     BOOLEAN NOT NULL DEFAULT TRUE,
    cache_ttl_sec          INT NOT NULL DEFAULT 60 CHECK (cache_ttl_sec BETWEEN 0 AND 3600),
    timeout_sec            INT NOT NULL DEFAULT 8 CHECK (timeout_sec BETWEEN 1 AND 60),
    last_error             TEXT NOT NULL DEFAULT '',
    last_check_at          TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by             UUID REFERENCES users(id)
);

INSERT INTO itsm_settings (id) VALUES (1)
ON CONFLICT DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS itsm_settings;
