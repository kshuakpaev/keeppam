CREATE DATABASE appdb;
\connect appdb

CREATE TABLE IF NOT EXISTS tickets (
    id          SERIAL PRIMARY KEY,
    title       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',
    amount      NUMERIC(12,2) NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO tickets (title, status, amount) VALUES
    ('Toll plaza A — incident', 'open', 1200.00),
    ('BRDC nightly reconcile', 'done', 0),
    ('Lane 4 sensor fault', 'open', 350.50);

COMMENT ON TABLE tickets IS 'KeepPAM demo table for SQL console / ephemeral roles';
