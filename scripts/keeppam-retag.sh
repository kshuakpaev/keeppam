#!/usr/bin/env bash
# Retag upstream runtime images to KeepPAM brand names (T-03).
# Usage: ./scripts/keeppam-retag.sh [image-brand-map.txt]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAP="${1:-$ROOT/deploy/image-brand-map.txt}"

if [[ ! -f "$MAP" ]]; then
  echo "brand map not found: $MAP" >&2
  exit 1
fi

n=0
skip=0
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%%#*}"
  line="$(echo "$line" | tr -d ' \t')"
  [[ -z "$line" ]] && continue
  src="${line%%=*}"
  dst="${line#*=}"
  if [[ -z "$src" || -z "$dst" || "$src" == "$dst" ]]; then
    continue
  fi
  if ! docker image inspect "$src" >/dev/null 2>&1; then
    skip=$((skip + 1))
    continue
  fi
  docker tag "$src" "$dst"
  echo "  $src → $dst"
  n=$((n + 1))
done < "$MAP"

echo "retag ok tagged=$n skipped_missing=$skip"
