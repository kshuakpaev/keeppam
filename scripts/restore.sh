#!/usr/bin/env bash
# KeepPAM restore from backup produced by scripts/backup.sh
# Usage: ./scripts/restore.sh /path/to/keeppam-YYYYMMDDTHHMMSSZ
# WARNING: destructive for DB and recordings.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="$ROOT/deploy/docker-compose.yml"
BASE="${1:-}"
if [[ -z "$BASE" || ! -f "${BASE}-db.sql" ]]; then
  echo "Usage: $0 /path/to/keeppam-TIMESTAMP" >&2
  echo "Expects: \${BASE}-db.sql and optionally \${BASE}-recordings.tar.gz" >&2
  exit 1
fi

echo "== STOP api/session-worker =="
docker compose -f "$COMPOSE" stop api session-worker

echo "== restore database =="
docker compose -f "$COMPOSE" exec -T postgres \
  psql -U keeppam -d keeppam -v ON_ERROR_STOP=1 -c \
  "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='keeppam' AND pid <> pg_backend_pid();" || true
docker compose -f "$COMPOSE" exec -T postgres \
  psql -U keeppam -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS keeppam;"
docker compose -f "$COMPOSE" exec -T postgres \
  psql -U keeppam -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE keeppam OWNER keeppam;"
docker compose -f "$COMPOSE" exec -T postgres \
  psql -U keeppam -d keeppam -v ON_ERROR_STOP=1 < "${BASE}-db.sql"

if [[ -f "${BASE}-recordings.tar.gz" ]]; then
  echo "== restore recordings =="
  docker run --rm -v deploy_recordings:/data -v "$(dirname "$BASE"):/backup:ro" alpine \
    sh -c "rm -rf /data/*; tar -xzf /backup/$(basename "$BASE")-recordings.tar.gz -C /data"
fi

echo "== START api/session-worker =="
docker compose -f "$COMPOSE" start api session-worker
echo "Restore complete. Verify /healthz and audit integrity."
