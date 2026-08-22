#!/usr/bin/env bash
# KeepPAM SOW-GEO-HA: push recordings from primary site to standby (rsync).
# Usage: KEEPPAM_GEO_RSYNC_TARGET=user@site-b:/data/recordings ./scripts/geo-recordings-sync.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="$ROOT/deploy/docker-compose.yml"
TARGET="${KEEPPAM_GEO_RSYNC_TARGET:-}"
SOURCE="${KEEPPAM_GEO_RSYNC_SOURCE:-}"

if [[ -z "$TARGET" ]]; then
  echo "KEEPPAM_GEO_RSYNC_TARGET required (e.g. backup@10.0.2.10:/var/keeppam/recordings)" >&2
  exit 1
fi

if [[ -z "$SOURCE" ]]; then
  # Prefer host path from compose volume
  if docker compose -f "$COMPOSE" ps api &>/dev/null; then
    SOURCE="$(docker compose -f "$COMPOSE" exec -T api sh -c 'echo -n "${KEEPPAM_RECORDINGS_DIR:-/tmp/recordings}"' 2>/dev/null || true)"
  fi
  SOURCE="${SOURCE:-$ROOT/recordings}"
fi

echo "== geo recordings rsync =="
echo "source=$SOURCE target=$TARGET"
rsync -az --partial "${SOURCE%/}/" "$TARGET"
echo "done"
