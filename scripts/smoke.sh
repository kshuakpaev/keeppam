#!/usr/bin/env bash
set -euo pipefail

API="${API:-http://localhost:8080}"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

echo "== health =="
curl -sf "$API/healthz" | grep -q ok

echo "== login bootstrap admin =="
LOGIN=$(curl -sf -c "$COOKIE_JAR" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"ChangeMeNow!1"}' \
  "$API/api/v1/auth/login")
echo "$LOGIN" | grep -Eq '"status":"(ok|must_setup)"'

CSRF=$(grep kp_csrf "$COOKIE_JAR" | awk '{print $NF}')
echo "csrf=$CSRF"

echo "== me =="
ME=$(curl -sf -b "$COOKIE_JAR" "$API/api/v1/auth/me")
echo "$ME" | grep -q '"username":"admin"'

echo "== change password =="
curl -sf -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" \
  -d '{"current_password":"ChangeMeNow!1","new_password":"AdminPass!234"}' \
  "$API/api/v1/auth/password" >/dev/null

CSRF=$(grep kp_csrf "$COOKIE_JAR" | awk '{print $NF}')

echo "== mfa setup =="
SETUP=$(curl -sf -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" \
  -X POST "$API/api/v1/auth/mfa/setup")
SECRET=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["secret"])' <<<"$SETUP")
CODE=$(python3 - <<PY
import hmac, struct, hashlib, time, base64
secret = "$SECRET"
# base32 decode
pad = '=' * ((8 - len(secret) % 8) % 8)
key = base64.b32decode(secret.upper() + pad)
counter = int(time.time()) // 30
msg = struct.pack('>Q', counter)
h = hmac.new(key, msg, hashlib.sha1).digest()
o = h[-1] & 0x0F
code = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
print(f'{code:06d}')
PY
)
CSRF=$(grep kp_csrf "$COOKIE_JAR" | awk '{print $NF}')
curl -sf -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" \
  -d "{\"code\":\"$CODE\"}" \
  "$API/api/v1/auth/mfa/confirm" >/dev/null

CSRF=$(grep kp_csrf "$COOKIE_JAR" | awk '{print $NF}')

echo "== create operator =="
CREATE=$(curl -sf -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" \
  -d '{"username":"ops1","email":"ops1@example.com","display_name":"Ops One","roles":["operator"]}' \
  "$API/api/v1/admin/users")
echo "$CREATE" | grep -q '"username":"ops1"'
TEMP=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("temporary_password",""))' <<<"$CREATE")
test -n "$TEMP"

echo "== list users =="
curl -sf -b "$COOKIE_JAR" "$API/api/v1/admin/users" | grep -q ops1

echo "== audit events =="
curl -sf -b "$COOKIE_JAR" "$API/api/v1/admin/audit-events" | grep -q user.created

echo "== operator cannot write users =="
OPJAR="$(mktemp)"
curl -sf -c "$OPJAR" -H 'Content-Type: application/json' \
  -d "{\"username\":\"ops1\",\"password\":\"$TEMP\"}" \
  "$API/api/v1/auth/login" >/dev/null
OPCSRF=$(grep kp_csrf "$OPJAR" | awk '{print $NF}')
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b "$OPJAR" \
  -H "Content-Type: application/json" -H "X-CSRF-Token: $OPCSRF" \
  -d '{"username":"x","email":"x@x.com","roles":["operator"]}' \
  "$API/api/v1/admin/users")
rm -f "$OPJAR"
test "$CODE" = "403"

echo "SMOKE OK"
