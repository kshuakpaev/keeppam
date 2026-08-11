#!/usr/bin/env bash
# KeepPAM backup: PostgreSQL dump + recordings tarball.
# Usage: ./scripts/backup.sh [backup_dir]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="$ROOT/deploy/docker-compose.yml"
OUT="${1:-$ROOT/backups}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
BASE="$OUT/keeppam-$TS"

echo "== pg_dump via compose postgres =="
docker compose -f "$COMPOSE" exec -T postgres \
  pg_dump -U keeppam -d keeppam --no-owner --no-acl > "$BASE-db.sql"

echo "== recordings volume =="
# Copy from api container recordings mount
docker compose -f "$COMPOSE" exec -T api \
  tar -czf - -C /tmp recordings > "$BASE-recordings.tar.gz" 2>/dev/null \
  || docker run --rm -v deploy_recordings:/data:ro alpine tar -czf - -C /data . > "$BASE-recordings.tar.gz"

BYTES=$(du -cb "$BASE-db.sql" "$BASE-recordings.tar.gz" 2>/dev/null | tail -1 | awk '{print $1}')
echo "status=ok path=$BASE bytes=${BYTES:-0}" | tee "$BASE.meta"
echo "Done: $BASE-db.sql + $BASE-recordings.tar.gz"
echo "Mark in UI: Compliance → DR → or POST /api/v1/admin/dr/backup after API-side backup"
