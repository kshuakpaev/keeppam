#!/usr/bin/env bash
# SOW-GEO-HA phase 3: verify DNS/VIP cutover points to expected site.
# Usage:
#   KEEPPAM_GEO_PUBLIC_URL=https://pam.corp \
#   KEEPPAM_GEO_EXPECT_SITE_ID=site-b \
#   KEEPPAM_GEO_EXPECT_ROLE=primary \
#   ./scripts/geo-cutover.sh
set -euo pipefail
PUBLIC="${KEEPPAM_GEO_PUBLIC_URL:-}"
EXPECT_ID="${KEEPPAM_GEO_EXPECT_SITE_ID:-}"
EXPECT_ROLE="${KEEPPAM_GEO_EXPECT_ROLE:-primary}"

if [[ -z "$PUBLIC" ]]; then
  echo "KEEPPAM_GEO_PUBLIC_URL required (user-facing URL after DNS/VIP flip)" >&2
  exit 1
fi

URL="${PUBLIC%/}/geoz"
echo "== geo cutover verify =="
echo "GET $URL"
BODY="$(curl -sf "$URL")"
echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"

SID="$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('site_id',''))" 2>/dev/null || true)"
ROLE="$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('role',''))" 2>/dev/null || true)"
WRITES="$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('allows_writes',''))" 2>/dev/null || true)"

err=0
if [[ -n "$EXPECT_ID" && "$SID" != "$EXPECT_ID" ]]; then
  echo "FAIL site_id=$SID expected $EXPECT_ID" >&2
  err=1
fi
if [[ -n "$EXPECT_ROLE" && "$ROLE" != "$EXPECT_ROLE" ]]; then
  echo "FAIL role=$ROLE expected $EXPECT_ROLE" >&2
  err=1
fi
if [[ "$EXPECT_ROLE" == "primary" && "$WRITES" != "True" && "$WRITES" != "true" ]]; then
  echo "WARN allows_writes=$WRITES (primary should allow writes)" >&2
fi
if [[ "$err" -ne 0 ]]; then
  exit 1
fi
echo "CUTOVER OK site_id=$SID role=$ROLE allows_writes=$WRITES"
