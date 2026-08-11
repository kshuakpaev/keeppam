-- +goose Up

CREATE TABLE ssh_settings (
    id                 INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    ssh_auth_mode      TEXT NOT NULL DEFAULT 'vault_secret'
                       CHECK (ssh_auth_mode IN ('vault_secret', 'ssh_cert')),
    ssh_ca_private_enc BYTEA,
    ssh_ca_public      TEXT NOT NULL DEFAULT '',
    ssh_cert_ttl_hours INT NOT NULL DEFAULT 8
                       CHECK (ssh_cert_ttl_hours >= 1 AND ssh_cert_ttl_hours <= 168),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by         UUID REFERENCES users(id)
);

INSERT INTO ssh_settings (id) VALUES (1);

-- +goose Down
DROP TABLE IF EXISTS ssh_settings;
