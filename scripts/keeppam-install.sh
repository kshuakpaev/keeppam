#!/usr/bin/env bash
# First-time install from git checkout or an offline bundle (USB/ISO).
# Does not pull images. Usage:
#   ./scripts/keeppam-install.sh [bundle.tar.gz|bundle-dir]
#   KEEPPAM_HA=1 KEEPPAM_OBS=1 ./scripts/keeppam-install.sh ./dist/keeppam-1.0.0-offline-full
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# If this tree is an unpacked bundle, ROOT is the bundle root (has images.tar + deploy/).
BUNDLE="${1:-}"
API="${API:-http://127.0.0.1:8080}"

# shellcheck source=keeppam-compose.inc.sh
source "$ROOT/scripts/keeppam-compose.inc.sh"

keeppam_need_docker

if [[ -n "$BUNDLE" ]]; then
  unpack() {
    local src="$1"
    if [[ -d "$src" ]]; then
      echo "$src"
      return
    fi
    [[ -f "$src" ]] || { echo "not found: $src" >&2; exit 1; }
    local tmp inner
    tmp="$(mktemp -d /tmp/keeppam-install.XXXXXX)"
    tar -xzf "$src" -C "$tmp"
    inner="$(find "$tmp" -maxdepth 1 -mindepth 1 -type d | head -1)"
    echo "$inner"
  }
  DIR="$(unpack "$BUNDLE")"
  if [[ -f "$DIR/SHA256SUMS" && -f "$DIR/images.tar" ]]; then
    echo "== verify checksums =="
    ( cd "$DIR" && sha256sum -c SHA256SUMS )
    echo "== docker load =="
    docker load -i "$DIR/images.tar"
  fi
  if [[ -z "${KEEPPAM_OBS:-}" ]] && grep -q '^set=full' "$DIR/MANIFEST.txt" 2>/dev/null; then
    KEEPPAM_OBS=1
  fi
  # Bundle may be a full tree (deploy/ + scripts/) — prefer it as ROOT.
  if [[ -f "$DIR/deploy/docker-compose.yml" ]]; then
    ROOT="$DIR"
    # shellcheck source=keeppam-compose.inc.sh
    source "$ROOT/scripts/keeppam-compose.inc.sh"
  fi
elif [[ -f "$ROOT/images.tar" ]]; then
  echo "== docker load (bundle root) =="
  if [[ -f "$ROOT/SHA256SUMS" ]]; then
    ( cd "$ROOT" && sha256sum -c SHA256SUMS )
  fi
  docker load -i "$ROOT/images.tar"
  if [[ -z "${KEEPPAM_OBS:-}" ]] && grep -q '^set=full' "$ROOT/MANIFEST.txt" 2>/dev/null; then
    KEEPPAM_OBS=1
  fi
fi

KEEPPAM_OBS="${KEEPPAM_OBS:-0}"

if [[ ! -f "$ROOT/deploy/docker-compose.yml" ]]; then
  echo "no deploy/docker-compose.yml under $ROOT" >&2
  exit 1
fi

if [[ ! -f "$ROOT/deploy/.env" && -f "$ROOT/deploy/.env.example" ]]; then
  cp "$ROOT/deploy/.env.example" "$ROOT/deploy/.env"
  echo "wrote $ROOT/deploy/.env from .env.example — change the bootstrap password"
fi

if [[ ! -f "$ROOT/deploy/auth-server" ]]; then
  echo "== extract auth-server from deploy-api:latest =="
  cid="$(docker create deploy-api:latest)"
  docker cp "$cid:/app/auth-server" "$ROOT/deploy/auth-server"
  docker rm "$cid" >/dev/null
  chmod +x "$ROOT/deploy/auth-server"
fi

if [[ ! -d "$ROOT/services/auth/migrations" ]]; then
  echo "missing services/auth/migrations (API will not migrate)" >&2
  exit 1
fi

echo "== compose up --pull never --no-build (no registry) =="
keeppam_compose up -d --pull never --no-build

echo "== wait /readyz =="
if ! keeppam_wait_ready; then
  echo "readyz did not become healthy. Logs: docker compose -f $ROOT/deploy/docker-compose.yml logs api" >&2
  exit 1
fi

VER="$(tr -d ' \n' < "$ROOT/VERSION" 2>/dev/null || echo unknown)"
echo "install ok version=$VER"
echo "Portal: http://127.0.0.1:5173  API: $API"
echo "Admin password: deploy/.env KEEPPAM_BOOTSTRAP_ADMIN_PASSWORD (default ChangeMeNow!1)"
echo "NOTICE: $ROOT/NOTICE"
echo "No vendor callback; images were not pulled."
