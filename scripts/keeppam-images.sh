#!/usr/bin/env bash
# Print image names for the offline bundle (one per line).
# SET=core|full  (default core)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SET="${SET:-core}"
grep -vE '^\s*(#|$)' "$ROOT/deploy/images-core.txt"
if [[ "$SET" == "full" ]]; then
  grep -vE '^\s*(#|$)' "$ROOT/deploy/images-full.txt"
fi
