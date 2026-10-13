#!/usr/bin/env bash
# Production HA in one DC: 2+2 (or 3+2) + Postgres auto-failover (repmgr + Pgpool).
# Geo standby is a second site: KEEPPAM_GEO=1 (do not combine with PGHA on the same compose).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export KEEPPAM_HA="${KEEPPAM_HA:-1}"
export KEEPPAM_PGHA="${KEEPPAM_PGHA:-1}"
# shellcheck source=keeppam-compose.inc.sh
. "$ROOT/scripts/keeppam-compose.inc.sh"
keeppam_need_docker
cd "$ROOT/deploy"
keeppam_compose up -d "$@"
