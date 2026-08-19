#!/usr/bin/env bash
# Restore image tags recorded by keeppam-upgrade.sh, then compose up.
# Usage: ./scripts/keeppam-rollback.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$ROOT/deploy/.upgrade-state"
API="${API:-http://127.0.0.1:8080}"

# shellcheck source=keeppam-compose.inc.sh
source "$ROOT/scripts/keeppam-compose.inc.sh"

keeppam_need_docker

if [[ ! -s "$STATE" ]]; then
  echo "no rollback state at $STATE" >&2
  exit 1
fi

echo "== retag previous image ids =="
while read -r img id; do
  [[ -z "${img:-}" || -z "${id:-}" ]] && continue
  docker tag "$id" "$img"
  echo "  $img <- $id"
done < "$STATE"

echo "== compose up --pull never --no-build =="
keeppam_compose up -d --pull never --no-build

if ! keeppam_wait_ready; then
  echo "rollback started but API not healthy yet; check compose logs" >&2
  exit 1
fi
echo "rollback ok"
