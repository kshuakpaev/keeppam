#!/bin/sh
# Physical streaming replica of compose service `postgres`.
# Not automatic failover — promote manually (see docs/ha.txt).
set -eu
DATA="${PGDATA:-/var/lib/postgresql/data}"
if [ ! -f "$DATA/PG_VERSION" ]; then
  echo "waiting for primary..."
  until pg_isready -h "$PGHOST" -p "$PGPORT" -U "$PGUSER"; do
    sleep 2
  done
  echo "basebackup from $PGHOST"
  rm -rf "$DATA"/*
  PGPASSWORD="$PGPASSWORD" pg_basebackup -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -D "$DATA" -Fp -Xs -P -R
fi
chown -R postgres:postgres "$DATA" 2>/dev/null || true
exec docker-entrypoint.sh postgres
