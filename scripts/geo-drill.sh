#!/usr/bin/env bash
# SOW-GEO-HA phase 3: acceptance drill (non-destructive).
# Usage:
#   ./scripts/geo-drill.sh
#   API=http://127.0.0.1:8080 KEEPPAM_GEO_PUBLIC_URL=http://pam.example ./scripts/geo-drill.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="${API:-http://127.0.0.1:8080}"
PUBLIC="${KEEPPAM_GEO_PUBLIC_URL:-$API}"
fail=0
pass=0

ok() { echo "PASS  $*"; pass=$((pass + 1)); }
bad() { echo "FAIL  $*"; fail=$((fail + 1)); }
info() { echo "INFO  $*"; }

echo "== KeepPAM geo-HA drill =="
echo "API=$API PUBLIC=$PUBLIC"
echo

GEOZ="$(curl -sf "$API/geoz" || true)"
if [[ -n "$GEOZ" ]] && echo "$GEOZ" | grep -q site_id; then
  ok "GET /geoz"
  info "geoz=$GEOZ"
else
  bad "GET /geoz"
fi

if curl -sf "$API/readyz" | grep -qE 'ready|draining'; then
  ok "GET /readyz"
else
  bad "GET /readyz"
fi

if [[ -f "$ROOT/docs/geo-ha-cutover.txt" ]]; then
  ok "playbook geo-ha-cutover.txt"
else
  bad "missing docs/geo-ha-cutover.txt"
fi

for s in geo-drill.sh geo-cutover.sh geo-promote.sh geo-recordings-sync.sh; do
  if [[ -x "$ROOT/scripts/$s" ]]; then ok "script $s"; else bad "script $s"; fi
done

# Public cutover endpoint (may equal API on lab)
PZ="$(curl -sf "${PUBLIC%/}/geoz" || true)"
if [[ -n "$PZ" ]] && echo "$PZ" | grep -q site_id; then
  ok "public /geoz ($PUBLIC)"
else
  info "public /geoz unreachable — set KEEPPAM_GEO_PUBLIC_URL after DNS/VIP cutover"
fi

if [[ -f "$ROOT/deploy/compose.geo-standby.yml" ]]; then
  ok "compose.geo-standby.yml"
else
  bad "compose.geo-standby.yml"
fi

echo
echo "== summary: pass=$pass fail=$fail =="
if [[ "$fail" -gt 0 ]]; then
  exit 1
fi
echo "GEO DRILL OK (automated subset — full drill via GET /api/v1/admin/geo/drill with session)"
exit 0
