#!/usr/bin/env bash
# KeepPAM product version helper (semver MAJOR.MINOR.PATCH in ./VERSION).
#
# Usage:
#   ./scripts/keeppam-version.sh              # print current
#   ./scripts/keeppam-version.sh show
#   ./scripts/keeppam-version.sh bump          # BUMP=patch|minor|major (default patch)
#   BUMP=none ./scripts/keeppam-version.sh bump  # no change, print current
#   BUMP=minor ./scripts/keeppam-version.sh bump
#
# Writes VERSION and appends a line to VERSION_HISTORY.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILE="$ROOT/VERSION"
HIST="$ROOT/VERSION_HISTORY"
ACTION="${1:-show}"
BUMP="${BUMP:-patch}"

read_ver() {
  if [[ ! -f "$FILE" ]]; then
    echo "0.0.0"
    return
  fi
  tr -d ' \n\r' < "$FILE"
  echo
}

parse_semver() {
  local v="$1"
  if [[ ! "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)([+-][0-9A-Za-z.-]+)?$ ]]; then
    echo "invalid VERSION '$v' (want MAJOR.MINOR.PATCH)" >&2
    exit 1
  fi
  MAJOR="${BASH_REMATCH[1]}"
  MINOR="${BASH_REMATCH[2]}"
  PATCH="${BASH_REMATCH[3]}"
}

bump_ver() {
  local kind="$1"
  parse_semver "$(read_ver)"
  case "$kind" in
    none|"")
      ;;
    patch)
      PATCH=$((PATCH + 1))
      ;;
    minor)
      MINOR=$((MINOR + 1))
      PATCH=0
      ;;
    major)
      MAJOR=$((MAJOR + 1))
      MINOR=0
      PATCH=0
      ;;
    *)
      echo "BUMP must be none|patch|minor|major (got: $kind)" >&2
      exit 1
      ;;
  esac
  echo "${MAJOR}.${MINOR}.${PATCH}"
}

case "$ACTION" in
  show|get|print|"")
    read_ver
    ;;
  bump)
    OLD="$(read_ver)"
    NEW="$(bump_ver "$BUMP")"
    if [[ "$NEW" != "$OLD" ]]; then
      printf '%s\n' "$NEW" > "$FILE"
      mkdir -p "$(dirname "$HIST")"
      printf '%s\t%s\t%s\tbump=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$OLD" "$NEW" "$BUMP" >> "$HIST"
      echo "version: $OLD → $NEW" >&2
    else
      echo "version: $NEW (unchanged)" >&2
    fi
    echo "$NEW"
    ;;
  *)
    echo "usage: $0 [show|bump]" >&2
    exit 1
    ;;
esac
