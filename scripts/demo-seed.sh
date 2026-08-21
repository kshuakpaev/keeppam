#!/usr/bin/env bash
# Seed sales-demo personas and assets (idempotent).
# Admin must already be able to log in. If MFA is on: ADMIN_TOTP=123456
# Usage:
#   ADMIN_PASSWORD='ChangeMeNow!1' ./scripts/demo-seed.sh
#   DEMO_RDP_HOST=10.0.0.50 DEMO_RDP_USER=Administrator DEMO_RDP_PASS='…' ./scripts/demo-seed.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="${API:-http://127.0.0.1:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-ChangeMeNow!1}"
OPS_PASSWORD="${OPS_PASSWORD:-DemoOps!23456}"
AUD_PASSWORD="${AUD_PASSWORD:-DemoAud!23456}"
OUT="${OUT:-$ROOT/deploy/.demo-seed.txt}"

export API ADMIN_USER ADMIN_PASSWORD OPS_PASSWORD AUD_PASSWORD
export DEMO_RDP_HOST="${DEMO_RDP_HOST:-}"
export DEMO_RDP_PORT="${DEMO_RDP_PORT:-3389}"
export DEMO_RDP_USER="${DEMO_RDP_USER:-Administrator}"
export DEMO_RDP_PASS="${DEMO_RDP_PASS:-}"
export ADMIN_TOTP="${ADMIN_TOTP:-}"

COOKIE="$(mktemp)"
trap 'rm -f "$COOKIE"' EXIT

csrf() { grep kp_csrf "$COOKIE" | awk '{print $NF}'; }

echo "== login $ADMIN_USER =="
LOGIN=$(curl -sf -c "$COOKIE" -H 'Content-Type: application/json' \
  -d "$(python3 -c 'import json,os; print(json.dumps({"username":os.environ["ADMIN_USER"],"password":os.environ["ADMIN_PASSWORD"]}))')" \
  "$API/api/v1/auth/login")
STATUS=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' <<<"$LOGIN")
if [[ "$STATUS" == "mfa_required" ]]; then
  if [[ -z "$ADMIN_TOTP" ]]; then
    echo "admin MFA is on. Re-run with ADMIN_TOTP=<6 digits>." >&2
    exit 1
  fi
  CHAL=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("challenge_token",""))' <<<"$LOGIN")
  export CHAL
  curl -sf -c "$COOKIE" -b "$COOKIE" -H 'Content-Type: application/json' \
    -d "$(python3 -c 'import json,os; print(json.dumps({"challenge_token":os.environ["CHAL"],"code":os.environ["ADMIN_TOTP"]}))')" \
    "$API/api/v1/auth/mfa/verify" >/dev/null
fi
CSRF=$(csrf)
if [[ -z "$CSRF" ]]; then
  echo "login failed (no csrf). Finish /setup as admin or check ADMIN_PASSWORD." >&2
  echo "$LOGIN" >&2
  exit 1
fi

api() {
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -sf -b "$COOKIE" -c "$COOKIE" \
      -H "Content-Type: application/json" -H "X-CSRF-Token: $(csrf)" \
      -X "$method" -d "$body" "$API$path"
  else
    curl -sf -b "$COOKIE" "$API$path"
  fi
}

USERS=$(api GET /api/v1/admin/users)
create_user() {
  local name="$1" email="$2" display="$3" role="$4" pass="$5"
  if echo "$USERS" | python3 -c 'import json,sys
name=sys.argv[1]
d=json.load(sys.stdin)
sys.exit(0 if any(u.get("username")==name for u in d.get("users") or []) else 1)' "$name"; then
    echo "user exists: $name"
    return
  fi
  export N="$name" E="$email" D="$display" R="$role" PW="$pass"
  api POST /api/v1/admin/users "$(python3 -c 'import json,os; print(json.dumps({"username":os.environ["N"],"email":os.environ["E"],"display_name":os.environ["D"],"roles":[os.environ["R"]],"password":os.environ["PW"]}))')" >/dev/null
  echo "created user $name"
  USERS=$(api GET /api/v1/admin/users)
}

create_user ops ops@keeppam.demo "Demo Operator" operator "$OPS_PASSWORD"
create_user auditor auditor@keeppam.demo "Demo Auditor" auditor "$AUD_PASSWORD"

ASSETS=$(api GET /api/v1/admin/assets)

asset_id_by_name() {
  python3 -c 'import json,sys
name=sys.argv[1]
d=json.load(sys.stdin)
for a in d.get("assets") or []:
    if a.get("name")==name:
        print(a.get("id",""))
        break' "$1" <<<"$ASSETS"
}

create_asset() {
  local name="$1" body="$2"
  local id
  id=$(asset_id_by_name "$name")
  if [[ -n "$id" ]]; then
    echo "asset exists: $name" >&2
    printf '%s' "$id"
    return
  fi
  local created
  created=$(api POST /api/v1/admin/assets "$body")
  id=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))' <<<"$created")
  echo "created asset $name" >&2
  ASSETS=$(api GET /api/v1/admin/assets)
  printf '%s' "$id"
}

LINUX_ID=$(create_asset demo-linux-01 "$(python3 -c 'import json; print(json.dumps({"name":"demo-linux-01","asset_type":"host","hostname":"demo-linux-01","address":"demo-ssh","port":22,"protocol":"ssh","description":"Sales demo SSH","tags":["demo","linux"],"approval_mode":"sequential","approval_stages":["manager"]}))')")
echo
DB_ID=$(create_asset demo-tickets-db "$(python3 -c 'import json; print(json.dumps({"name":"demo-tickets-db","asset_type":"db","hostname":"tickets","address":"demo-postgres","port":5432,"protocol":"postgres","database_name":"appdb","description":"Sales demo PostgreSQL","tags":["demo","db"],"approval_mode":"sequential","approval_stages":["manager"]}))')")
echo

ensure_account() {
  local asset="$1" user="$2" secret="$3" desc="$4"
  local accs has
  accs=$(api GET "/api/v1/admin/assets/$asset")
  has=$(python3 -c 'import json,sys
u=sys.argv[1]
d=json.load(sys.stdin)
print("1" if any(a.get("username")==u for a in d.get("accounts") or []) else "")' "$user" <<<"$accs")
  if [[ "$has" == "1" ]]; then
    echo "account exists: $user"
    return
  fi
  export U="$user" S="$secret" DSC="$desc"
  api POST "/api/v1/admin/assets/$asset/accounts" "$(python3 -c 'import json,os; print(json.dumps({"username":os.environ["U"],"auth_method":"password","secret":os.environ["S"],"description":os.environ["DSC"]}))')" >/dev/null
  echo "created account $user"
}

ensure_account "$LINUX_ID" demo "DemoPass!1" "compose demo-ssh"
ensure_account "$DB_ID" pam "demo" "compose demo-postgres"

WIN_NOTE="not created — set DEMO_RDP_HOST, DEMO_RDP_USER, DEMO_RDP_PASS and re-run"
if [[ -n "$DEMO_RDP_HOST" && -n "$DEMO_RDP_PASS" ]]; then
  WIN_ID=$(create_asset demo-win-01 "$(python3 -c 'import json,os; print(json.dumps({"name":"demo-win-01","asset_type":"host","hostname":"demo-win-01","address":os.environ["DEMO_RDP_HOST"],"port":int(os.environ.get("DEMO_RDP_PORT") or "3389"),"protocol":"rdp","description":"Sales demo RDP","tags":["demo","windows"],"approval_mode":"sequential","approval_stages":["manager"]}))')")
  echo
  ensure_account "$WIN_ID" "$DEMO_RDP_USER" "$DEMO_RDP_PASS" "lab Windows"
  WIN_NOTE="rdp ${DEMO_RDP_HOST}:${DEMO_RDP_PORT} account=${DEMO_RDP_USER}"
fi

{
  echo "KeepPAM demo seed"
  echo "portal=http://127.0.0.1:5173"
  echo "api=$API"
  echo "ssh_gateway: ssh -p 2222 ops@127.0.0.1"
  echo
  echo "admin=$ADMIN_USER  (existing)"
  echo "ops=ops  password=$OPS_PASSWORD  first login: /setup TOTP"
  echo "auditor=auditor  password=$AUD_PASSWORD  first login: /setup TOTP"
  echo "approver=admin  (access.approve)"
  echo
  echo "demo-linux-01  ssh://demo-ssh:22  vault user demo"
  echo "demo-tickets-db  postgres://demo-postgres:5432/appdb  vault user pam"
  echo "demo-win-01  $WIN_NOTE"
  echo
  echo "typed marker: echo KEEP-PAM-DEMO-42"
  echo "runbook: docs/demo-45min.txt"
} | tee "$OUT"
echo "wrote $OUT"
