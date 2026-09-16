#!/usr/bin/env bash
# Apply an offline bundle on a host with no registry/internet.
# Usage: ./scripts/keeppam-upgrade.sh <bundle.tar.gz|bundle-dir>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$ROOT/deploy/.upgrade-state"
BUNDLE="${1:-}"
API="${API:-}"

# shellcheck source=keeppam-compose.inc.sh
source "$ROOT/scripts/keeppam-compose.inc.sh"

if [[ -z "$BUNDLE" ]]; then
  echo "Usage: $0 <keeppam-VERSION-offline-SET.tar.gz|dir>" >&2
  exit 1
fi

keeppam_need_docker

unpack() {
  local src="$1"
  if [[ -d "$src" ]]; then
    echo "$src"
    return
  fi
  if [[ ! -f "$src" ]]; then
    echo "not found: $src" >&2
    exit 1
  fi
  local tmp inner
  tmp="$(mktemp -d /tmp/keeppam-upgrade.XXXXXX)"
  tar -tzf "$src" >/dev/null
  tar -xzf "$src" -C "$tmp"
  inner="$(find "$tmp" -maxdepth 1 -mindepth 1 -type d | head -1)"
  echo "$inner"
}

DIR="$(unpack "$BUNDLE")"
if [[ ! -f "$DIR/images.tar" || ! -f "$DIR/SHA256SUMS" ]]; then
  echo "bundle missing images.tar / SHA256SUMS in $DIR" >&2
  exit 1
fi

if [[ -z "${KEEPPAM_OBS:-}" ]]; then
  if grep -q '^set=full' "$DIR/MANIFEST.txt" 2>/dev/null; then
    KEEPPAM_OBS=1
  else
    KEEPPAM_OBS=0
  fi
fi
KEEPPAM_BRAND="${KEEPPAM_BRAND:-1}"
export KEEPPAM_OBS KEEPPAM_BRAND

echo "== verify checksums =="
( cd "$DIR" && sha256sum -c SHA256SUMS )

echo "== snapshot running image ids for rollback =="
mkdir -p "$(dirname "$STATE")"
keeppam_snapshot_images "$STATE" "$DIR/images.txt"
echo "state=$STATE"

echo "== docker load (no registry) =="
docker load -i "$DIR/images.tar"

keeppam_retag

echo "== backup DB + recordings =="
"$ROOT/scripts/backup.sh" "$ROOT/backups" || echo "WARN: backup.sh failed; continue at your risk" >&2

echo "== compose up --pull never --no-build =="
keeppam_compose up -d --pull never --no-build

echo "== wait /readyz =="
if ! keeppam_wait_ready; then
  echo "readyz did not become healthy. Rollback: $ROOT/scripts/keeppam-rollback.sh" >&2
  exit 1
fi

echo "upgrade ok version=$(cat "$DIR/VERSION" 2>/dev/null || true)"
echo "API $API/readyz is up. On failure use scripts/keeppam-rollback.sh"
