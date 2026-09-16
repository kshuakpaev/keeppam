#!/usr/bin/env bash
# Rebind KeepPAM API on the host to port 8008 (or PORT=…).
# Container still listens on 8080; web :5173 keeps working via Docker DNS.
#
# From unpacked bundle (keeppam-*-offline-core) or git tree:
#   chmod +x deploy/patches/api-host-8008/apply.sh
#   ./deploy/patches/api-host-8008/apply.sh
#   # or: PORT=8008 ./deploy/patches/api-host-8008/apply.sh
set -euo pipefail

PORT="${PORT:-8008}"
HERE="$(cd "$(dirname "$0")" && pwd)"
if [[ -f "$HERE/../../../deploy/docker-compose.yml" ]]; then
  ROOT="$(cd "$HERE/../../.." && pwd)"
elif [[ -f "$HERE/../../docker-compose.yml" ]]; then
  ROOT="$(cd "$HERE/../.." && pwd)"
elif [[ -f ./deploy/docker-compose.yml ]]; then
  ROOT="$(pwd)"
else
  echo "run from KeepPAM tree (need deploy/docker-compose.yml)" >&2
  exit 1
fi

COMPOSE="$ROOT/deploy/docker-compose.yml"
ENVF="$ROOT/deploy/.env"
EX="$ROOT/deploy/.env.example"

if ! grep -Eq '^[0-9]+$' <<<"$PORT"; then
  echo "PORT must be a number (got: $PORT)" >&2
  exit 1
fi

echo "== tree $ROOT"
echo "== host API port $PORT (container :8080)"

if grep -q 'KEEPPAM_API_HOST_PORT' "$COMPOSE"; then
  echo "== compose already uses KEEPPAM_API_HOST_PORT"
else
  echo "== patch $COMPOSE host bind 8080:8080"
  if grep -q -- '- "8080:8080"' "$COMPOSE"; then
    sed -i 's|- "8080:8080"|- "${KEEPPAM_API_HOST_PORT:-8080}:8080"|' "$COMPOSE"
  elif grep -q -- "- '8080:8080'" "$COMPOSE"; then
    sed -i "s|- '8080:8080'|- \"\${KEEPPAM_API_HOST_PORT:-8080}:8080\"|" "$COMPOSE"
  else
    echo "warning: no 8080:8080 mapping found in $COMPOSE" >&2
  fi
fi

HA="$ROOT/deploy/compose.ha.yml"
if [[ -f "$HA" ]] && grep -q -- '- "8080:8080"' "$HA" && ! grep -q 'KEEPPAM_API_HOST_PORT' "$HA"; then
  echo "== patch compose.ha.yml edge bind"
  sed -i 's|- "8080:8080"|- "${KEEPPAM_API_HOST_PORT:-8080}:8080"|' "$HA"
fi

if [[ ! -f "$ENVF" && -f "$EX" ]]; then
  cp "$EX" "$ENVF"
  echo "== created $ENVF from .env.example"
fi
if [[ ! -f "$ENVF" ]]; then
  echo "KEEPPAM_API_HOST_PORT=$PORT" > "$ENVF"
  echo "== wrote $ENVF"
else
  if grep -qE '^[[:space:]]*KEEPPAM_API_HOST_PORT=' "$ENVF"; then
    sed -i "s|^[[:space:]]*KEEPPAM_API_HOST_PORT=.*|KEEPPAM_API_HOST_PORT=$PORT|" "$ENVF"
  else
    printf '\nKEEPPAM_API_HOST_PORT=%s\n' "$PORT" >> "$ENVF"
  fi
  echo "== $ENVF KEEPPAM_API_HOST_PORT=$PORT"
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  echo "== compose up (api :$PORT + web :5173 + workers)"
  compose_up() {
    if [[ -f "$ROOT/scripts/keeppam-compose.inc.sh" ]]; then
      # shellcheck source=/dev/null
      source "$ROOT/scripts/keeppam-compose.inc.sh"
      keeppam_compose up -d --pull never --no-build
    else
      ( cd "$ROOT/deploy" && docker compose --env-file .env up -d --no-build )
    fi
  }
  compose_up
  echo "== wait API :$PORT /readyz"
  ok=0
  for i in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:${PORT}/readyz" >/dev/null 2>&1 || curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 2
  done
  if [[ "$ok" != 1 ]]; then
    echo "API not healthy yet. Logs:" >&2
    ( cd "$ROOT/deploy" && docker compose logs --tail 80 api ) || true
    exit 1
  fi
  echo "== wait portal :5173"
  wok=0
  for i in $(seq 1 20); do
    if curl -sf -o /dev/null "http://127.0.0.1:5173/" 2>/dev/null || curl -sf -o /dev/null -I "http://127.0.0.1:5173/" 2>/dev/null; then
      wok=1
      break
    fi
    sleep 2
  done
  if [[ "$wok" != 1 ]]; then
    echo "Portal :5173 is not up. Check: docker compose -f $COMPOSE ps web" >&2
    ( cd "$ROOT/deploy" && docker compose ps && docker compose logs --tail 40 web ) || true
    exit 1
  fi
else
  echo "docker compose not found — patched files only. Recreate stack yourself."
fi

echo
echo "OK. Portal: http://<host>:5173"
echo "    API:    http://<host>:${PORT}"
echo "Host :8080 is free for the other service."
