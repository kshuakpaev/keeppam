#!/usr/bin/env bash
# KeepPAM SOW-GEO-HA: promote standby site (PG + role flip). Review plan first:
#   curl -s -b … /api/v1/admin/geo/promote/plan | jq
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="$ROOT/deploy/docker-compose.yml"
GEO_COMPOSE="$ROOT/deploy/compose.geo-standby.yml"

PG_ONLY=0
ROLE_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --pg-only) PG_ONLY=1 ;;
    --role-only) ROLE_ONLY=1 ;;
    -h|--help)
      echo "Usage: $0 [--pg-only|--role-only]"
      echo "  --pg-only    promote PostgreSQL standby only"
      echo "  --role-only  set KEEPPAM_SITE_ROLE=primary in deploy/.env and restart api/workers"
      exit 0
      ;;
  esac
done

run_pg_promote() {
  echo "== PostgreSQL promote =="
  if docker compose -f "$COMPOSE" -f "$GEO_COMPOSE" ps postgres &>/dev/null 2>&1; then
    docker compose -f "$COMPOSE" -f "$GEO_COMPOSE" exec -T postgres \
      pg_ctl promote -D /var/lib/postgresql/data -W || \
      docker compose -f "$COMPOSE" -f "$GEO_COMPOSE" exec -T postgres \
        psql -U keeppam -d keeppam -c "SELECT pg_promote();"
  else
    docker compose -f "$COMPOSE" exec -T postgres \
      pg_ctl promote -D /var/lib/postgresql/data -W || \
      docker compose -f "$COMPOSE" exec -T postgres \
        psql -U keeppam -d keeppam -c "SELECT pg_promote();"
  fi
  echo "PG promoted — verify pg_is_in_recovery() = false"
}

run_role_flip() {
  ENV_FILE="$ROOT/deploy/.env"
  echo "== flip KEEPPAM_SITE_ROLE=primary =="
  if [[ -f "$ENV_FILE" ]]; then
    if grep -q '^KEEPPAM_SITE_ROLE=' "$ENV_FILE"; then
      sed -i 's/^KEEPPAM_SITE_ROLE=.*/KEEPPAM_SITE_ROLE=primary/' "$ENV_FILE"
    else
      echo 'KEEPPAM_SITE_ROLE=primary' >> "$ENV_FILE"
    fi
  else
    echo "WARN: $ENV_FILE missing — export KEEPPAM_SITE_ROLE=primary manually" >&2
  fi
  echo "== restart api + session-worker =="
  docker compose -f "$COMPOSE" restart api session-worker 2>/dev/null || \
    docker compose -f "$COMPOSE" -f "$GEO_COMPOSE" restart api session-worker
  echo "done — switch DNS/VIP, then smoke login/JIT/SSH"
}

if [[ "$PG_ONLY" -eq 1 ]]; then
  run_pg_promote
  exit 0
fi
if [[ "$ROLE_ONLY" -eq 1 ]]; then
  run_role_flip
  exit 0
fi

echo "Full promote: PG then role (confirm site A is down)"
read -r -p "Continue? [y/N] " ans
[[ "${ans,,}" == "y" ]] || exit 1
run_pg_promote
run_role_flip
