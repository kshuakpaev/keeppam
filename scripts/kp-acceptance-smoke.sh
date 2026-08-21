#!/usr/bin/env bash
# Non-destructive smoke against a running KeepPAM stand for docs/kp-acceptance.txt.
# Does NOT change passwords / MFA. Exit 0 if all required checks pass.
#
# Usage:
#   ./scripts/kp-acceptance-smoke.sh
#   API=http://127.0.0.1:8080 ./scripts/kp-acceptance-smoke.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="${API:-http://127.0.0.1:8080}"
fail=0
pass=0

ok() { echo "PASS  $*"; pass=$((pass + 1)); }
bad() { echo "FAIL  $*"; fail=$((fail + 1)); }
info() { echo "INFO  $*"; }

echo "== KeepPAM acceptance smoke =="
echo "API=$API"
echo

# --- §6 health / docs ---
if curl -sf "$API/readyz" | grep -q ready; then
  ok "API /readyz"
else
  bad "API /readyz"
fi

if curl -sf "$API/healthz" >/dev/null; then
  ok "API /healthz"
else
  bad "API /healthz"
fi

for f in \
  "$ROOT/NOTICE" \
  "$ROOT/docs/kp.txt" \
  "$ROOT/docs/kp-acceptance.txt" \
  "$ROOT/docs/demo-45min.txt" \
  "$ROOT/docs/offline-update.txt" \
  "$ROOT/docs/runtime-brand.txt" \
  "$ROOT/docs/ha.txt" \
  "$ROOT/deploy/compose.branded.yml" \
  "$ROOT/deploy/image-brand-map.txt" \
  "$ROOT/scripts/keeppam-retag.sh" \
  "$ROOT/scripts/keeppam-install.sh" \
  "$ROOT/services/auth/migrations/093_x509_login.sql"
do
  if [[ -f "$f" ]]; then
    ok "artifact $(basename "$f")"
  else
    bad "missing $f"
  fi
done

# --- §1 identity surface ---
METHODS="$(curl -sf "$API/api/v1/auth/methods" || true)"
if [[ -n "$METHODS" ]] && echo "$METHODS" | grep -q '"mode"'; then
  ok "GET /auth/methods"
  info "methods=$METHODS"
else
  bad "GET /auth/methods"
fi

# cert_login key present after T-48 rebuild (optional if old binary)
if echo "$METHODS" | grep -q 'cert_login'; then
  ok "auth methods expose cert_login (T-48)"
else
  info "cert_login not in methods (rebuild api or mTLS off) — optional on lab without TLS"
fi

# --- §2/3 ports (gateway listeners on session-worker / api) ---
check_port() {
  local p="$1" label="$2"
  if (echo >/dev/tcp/127.0.0.1/"$p") >/dev/null 2>&1; then
    ok "listen :$p ($label)"
  else
    bad "listen :$p ($label)"
  fi
}
check_port 2222 "SSH gateway"
check_port 5173 "web portal"
check_port 8080 "API"

# optional protocol ports — INFO if down (scope-dependent)
for pair in "2323:Telnet" "2324:TN3270" "1081:Citrix SOCKS" "11433:MSSQL"; do
  p="${pair%%:*}"
  label="${pair#*:}"
  if (echo >/dev/tcp/127.0.0.1/"$p") >/dev/null 2>&1; then
    ok "listen :$p ($label)"
  else
    info ":$p ($label) not listening — skip if out of scope"
  fi
done

# --- T-03 brand map / compose merge ---
if ROOT="$ROOT" KEEPPAM_BRAND=1 bash -c '
  source "$ROOT/scripts/keeppam-compose.inc.sh"
  keeppam_compose config 2>/dev/null | grep -q keeppam-session-gateway
'; then
  ok "compose.branded → keeppam-session-gateway"
else
  bad "compose.branded keeppam-session-gateway"
fi

if ROOT="$ROOT" KEEPPAM_BRAND=1 bash -c '
  source "$ROOT/scripts/keeppam-compose.inc.sh"
  ! keeppam_compose config 2>/dev/null | grep -qE "guacamole/guacd|opensearchproject/"
'; then
  ok "branded config hides upstream guacd/opensearch tags"
else
  bad "branded config still shows upstream vendor tags"
fi

# NOTICE brand names
if grep -q 'keeppam-session-gateway' "$ROOT/NOTICE"; then
  ok "NOTICE lists keeppam-session-gateway"
else
  bad "NOTICE missing keeppam-session-gateway"
fi

echo
echo "== summary: pass=$pass fail=$fail =="
if [[ "$fail" -gt 0 ]]; then
  exit 1
fi
echo "ACCEPTANCE SMOKE OK (automated subset of docs/kp-acceptance.txt)"
exit 0
