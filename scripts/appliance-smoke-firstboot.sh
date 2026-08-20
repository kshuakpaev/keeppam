#!/usr/bin/env bash
# Smoke-test first-boot wizard non-interactively (structure only).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d /tmp/keeppam-fb-smoke.XXXXXX)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

mkdir -p "$TMP/opt/keeppam/deploy" "$TMP/opt/keeppam/scripts" "$TMP/var/lib/keeppam" "$TMP/etc"
cp "$ROOT/deploy/.env.example" "$TMP/opt/keeppam/deploy/.env.example"
cat >"$TMP/opt/keeppam/scripts/keeppam-install.sh" <<'EOF'
#!/bin/sh
echo "smoke-install ok"
exit 0
EOF
chmod +x "$TMP/opt/keeppam/scripts/keeppam-install.sh"

SMOKE_SCRIPT="$TMP/firstboot.sh"
python3 - "$ROOT/appliance/guest/keeppam-firstboot.sh" "$SMOKE_SCRIPT" <<'PY'
import sys
from pathlib import Path
src, dst = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text()
text = text.replace(
    'if [[ "$(id -u)" -ne 0 ]]; then\n  echo "keeppam-firstboot: must run as root" >&2\n  exit 1\nfi',
    "# smoke: skip root check",
)
text = text.replace(
    'hostnamectl set-hostname "$HOSTNAME_VAL" 2>/dev/null || echo "$HOSTNAME_VAL" >"$HOSTNAME_FILE"',
    'echo "$HOSTNAME_VAL" >"${HOSTNAME_FILE}"',
)
text = text.replace(
    'if command -v netplan >/dev/null 2>&1; then\n  netplan apply || true\nfi',
    "# smoke: skip netplan apply",
)
dst.write_text(text)
PY
chmod +x "$SMOKE_SCRIPT"

export KEEPPAM_FB_NONINTERACTIVE=1
export KEEPPAM_ROOT="$TMP/opt/keeppam"
export KEEPPAM_FB_DONE="$TMP/var/lib/keeppam/firstboot.done"
export KEEPPAM_NETPLAN="$TMP/etc/99-keeppam.yaml"
export HOSTNAME_FILE="$TMP/etc/hostname"
export HOSTNAME_VAL=keeppam-smoke
export NET_MODE=static
export IP_ADDR=10.9.9.50
export IP_PREFIX=24
export IP_GW=10.9.9.1
export IP_DNS=1.1.1.1
export ADMIN_PASS='SmokeTestX1'
export CORS_ORIGIN='http://10.9.9.50:5173'
export LDAP_URL=''

bash "$SMOKE_SCRIPT"

grep -q 'SmokeTestX1' "$TMP/opt/keeppam/deploy/.env"
grep -q '10.9.9.50/24' "$TMP/etc/99-keeppam.yaml"
test -f "$TMP/var/lib/keeppam/firstboot.done"
bash "$SMOKE_SCRIPT"
echo "appliance-smoke-firstboot: OK"
