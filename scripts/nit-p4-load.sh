#!/bin/bash
# NIT §4: concurrent portal checks (default 200) against KeepPAM API.
set -euo pipefail

BASE="${KEEPPAM_BASE:-http://127.0.0.1:8080}"
N="${PORTAL_N:-200}"
USER="${KEEPPAM_BOOTSTRAP_ADMIN:-admin}"
PASS="${KEEPPAM_BOOTSTRAP_ADMIN_PASSWORD:-ChangeMeNow!1}"
P="${PARALLEL:-20}"

echo "GET ${BASE}/readyz × ${N} (parallel ${P})"
seq 1 "$N" | xargs -n1 -P"$P" -I{} curl -sf -o /dev/null -m 8 "${BASE}/readyz"
echo "readyz ok"

echo "POST /api/v1/auth/login × ${N} (parallel ${P})"
seq 1 "$N" | xargs -n1 -P"$P" -I{} bash -c "
  code=\$(curl -s -o /dev/null -w '%{http_code}' -m 15 -X POST '${BASE}/api/v1/auth/login' \
    -H 'Content-Type: application/json' \
    -d '{\"username\":\"${USER}\",\"password\":\"${PASS}\"}')
  case \$code in
    200|401|403) ;;
    *) echo \"login HTTP \$code\"; exit 1 ;;
  esac
"
echo "login batch ok (200/401/403 = API ответил)"

if [ -n "${SSH_N:-}" ]; then
  echo "SSH_N is set: run your own parallel ssh to :2222 (user+ASSET). See docs/nit-p4.txt"
fi
