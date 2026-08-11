-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id              UUID PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL DEFAULT '',
    password_hash   TEXT NOT NULL,
    mfa_secret_enc  BYTEA,
    mfa_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled', 'locked')),
    auth_source     TEXT NOT NULL DEFAULT 'local',
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_count INT NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID REFERENCES users(id)
);

CREATE TABLE roles (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE permissions (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_role_bindings (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE audit_events (
    id            UUID PRIMARY KEY,
    ts            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id      UUID REFERENCES users(id),
    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id   TEXT NOT NULL DEFAULT '',
    ip            TEXT NOT NULL DEFAULT '',
    user_agent    TEXT NOT NULL DEFAULT '',
    payload       JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash     TEXT NOT NULL DEFAULT '',
    hash          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_audit_events_ts ON audit_events (ts DESC);
CREATE INDEX idx_audit_events_actor ON audit_events (actor_id, ts DESC);
CREATE INDEX idx_audit_events_action ON audit_events (action, ts DESC);
CREATE INDEX idx_users_status ON users (status);

-- Seed roles (fixed UUIDs for bootstrap)
INSERT INTO roles (id, name, description) VALUES
    ('01900000-0000-7000-8000-000000000001', 'admin', 'Full platform administration'),
    ('01900000-0000-7000-8000-000000000002', 'operator', 'Operational access without user admin'),
    ('01900000-0000-7000-8000-000000000003', 'auditor', 'Read-only audit and user listing');

INSERT INTO permissions (id, name, description) VALUES
    ('01900000-0000-7000-8000-000000000011', 'users.read', 'List and view users'),
    ('01900000-0000-7000-8000-000000000012', 'users.write', 'Create and update users'),
    ('01900000-0000-7000-8000-000000000013', 'users.reset_mfa', 'Reset user MFA'),
    ('01900000-0000-7000-8000-000000000014', 'audit.read', 'Read audit events'),
    ('01900000-0000-7000-8000-000000000015', 'self.read', 'Read own profile');

-- admin: all
INSERT INTO role_permissions (role_id, permission_id)
SELECT '01900000-0000-7000-8000-000000000001', id FROM permissions;

-- operator: self.read
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000002', '01900000-0000-7000-8000-000000000015');

-- auditor: users.read, audit.read, self.read
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-000000000011'),
    ('01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-000000000014'),
    ('01900000-0000-7000-8000-000000000003', '01900000-0000-7000-8000-000000000015');

-- +goose Down
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS user_role_bindings;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;
