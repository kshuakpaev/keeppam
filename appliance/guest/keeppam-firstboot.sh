#!/usr/bin/env bash
# KeepPAM Virtual Appliance — interactive first-boot wizard (console).
# Idempotent: exits if /var/lib/keeppam/firstboot.done exists.
# Non-interactive: set KEEPPAM_FB_NONINTERACTIVE=1 and env vars below.
set -euo pipefail

DONE_FLAG="${KEEPPAM_FB_DONE:-/var/lib/keeppam/firstboot.done}"
ROOT="${KEEPPAM_ROOT:-/opt/keeppam}"
DEPLOY="$ROOT/deploy"
ENV_FILE="$DEPLOY/.env"
NETPLAN_FILE="${KEEPPAM_NETPLAN:-/etc/netplan/99-keeppam.yaml}"
HOSTNAME_FILE="/etc/hostname"

mkdir -p "$(dirname "$DONE_FLAG")" /var/lib/keeppam

if [[ -f "$DONE_FLAG" ]]; then
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "keeppam-firstboot: must run as root" >&2
  exit 1
fi

prompt() {
  local var="$1" msg="$2" def="${3:-}"
  local val=""
  if [[ -n "${!var:-}" ]]; then
    return 0
  fi
  if [[ "${KEEPPAM_FB_NONINTERACTIVE:-0}" == "1" ]]; then
    printf -v "$var" '%s' "$def"
    return 0
  fi
  if [[ -n "$def" ]]; then
    read -r -p "$msg [$def]: " val || true
    val="${val:-$def}"
  else
    read -r -p "$msg: " val || true
  fi
  printf -v "$var" '%s' "$val"
}

echo
echo "============================================"
echo "  KeepPAM Virtual Appliance — first boot"
echo "============================================"
echo

prompt HOSTNAME_VAL "Hostname" "keeppam"
prompt NET_MODE "Network (dhcp|static)" "dhcp"

IP_PREFIX="${IP_PREFIX:-24}"
IP_GW="${IP_GW:-}"
IP_DNS="${IP_DNS:-8.8.8.8}"
IFACE="$(ip -o link show 2>/dev/null | awk -F': ' '$2 !~ /^(lo|docker|br-|veth)/ {print $2; exit}' || true)"
IFACE="${IFACE:-eth0}"

if [[ "${NET_MODE}" == "static" ]]; then
  prompt IP_ADDR "IPv4 address" "10.0.0.50"
  prompt IP_PREFIX "Prefix length" "24"
  prompt IP_GW "Gateway" "10.0.0.1"
  prompt IP_DNS "DNS" "8.8.8.8"
fi

prompt ADMIN_PASS "Bootstrap admin password" "ChangeMeNow!1"
prompt CORS_ORIGIN "Portal CORS origin (http://IP:5173)" "http://${IP_ADDR:-127.0.0.1}:5173"
prompt LDAP_URL "LDAP URL (optional, blank=skip)" ""

echo
echo "Applying configuration…"

hostnamectl set-hostname "$HOSTNAME_VAL" 2>/dev/null || echo "$HOSTNAME_VAL" >"$HOSTNAME_FILE"

if [[ "$NET_MODE" == "static" ]]; then
  cat >"$NETPLAN_FILE" <<EOF
network:
  version: 2
  ethernets:
    ${IFACE}:
      dhcp4: false
      addresses: ["${IP_ADDR}/${IP_PREFIX}"]
      routes:
        - to: default
          via: ${IP_GW}
      nameservers:
        addresses: [${IP_DNS}]
EOF
else
  cat >"$NETPLAN_FILE" <<EOF
network:
  version: 2
  ethernets:
    ${IFACE}:
      dhcp4: true
EOF
fi
if command -v netplan >/dev/null 2>&1; then
  netplan apply || true
fi

if [[ ! -d "$DEPLOY" ]]; then
  echo "keeppam-firstboot: missing $DEPLOY — bake offline bundle into image" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" && -f "$DEPLOY/.env.example" ]]; then
  cp "$DEPLOY/.env.example" "$ENV_FILE"
fi
if [[ ! -f "$ENV_FILE" ]]; then
  cat >"$ENV_FILE" <<EOF
KEEPPAM_BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PASS}
KEEPPAM_DATA_KEY=a2VlcHBhbS1sb2NhbC1kZXYta2V5LTMyLWJ5dGVzISE=
KEEPPAM_CORS_ORIGIN=${CORS_ORIGIN}
EOF
else
  if grep -q '^KEEPPAM_BOOTSTRAP_ADMIN_PASSWORD=' "$ENV_FILE"; then
    sed -i "s|^KEEPPAM_BOOTSTRAP_ADMIN_PASSWORD=.*|KEEPPAM_BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PASS}|" "$ENV_FILE"
  else
    echo "KEEPPAM_BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PASS}" >>"$ENV_FILE"
  fi
  if grep -q '^KEEPPAM_CORS_ORIGIN=' "$ENV_FILE"; then
    sed -i "s|^KEEPPAM_CORS_ORIGIN=.*|KEEPPAM_CORS_ORIGIN=${CORS_ORIGIN}|" "$ENV_FILE"
  else
    echo "KEEPPAM_CORS_ORIGIN=${CORS_ORIGIN}" >>"$ENV_FILE"
  fi
fi

if [[ -n "$LDAP_URL" ]]; then
  echo "# LDAP first-boot hint (configure in portal Config → Auth)" >>"$ENV_FILE"
  echo "# KEEPPAM_LDAP_URL=${LDAP_URL}" >>"$ENV_FILE"
  mkdir -p /var/lib/keeppam
  printf '%s\n' "$LDAP_URL" >/var/lib/keeppam/ldap-url.hint
fi

# Start stack if install script present
if [[ -x "$ROOT/scripts/keeppam-install.sh" ]]; then
  echo "== starting KeepPAM (compose, --pull never) =="
  ( cd "$ROOT" && KEEPPAM_OBS="${KEEPPAM_OBS:-0}" ./scripts/keeppam-install.sh ) || {
    echo "warn: install returned non-zero; check docker and $ROOT" >&2
  }
elif [[ -f "$ROOT/images.tar" && -x "$ROOT/install.sh" ]]; then
  ( cd "$ROOT" && ./install.sh ) || true
fi

date -u +%Y-%m-%dT%H:%M:%SZ >"$DONE_FLAG"
chmod 644 "$DONE_FLAG"

IP_SHOW="$(hostname -I 2>/dev/null | awk '{print $1}')"
IP_SHOW="${IP_SHOW:-${IP_ADDR:-<dhcp>}}"
echo
echo "First boot complete."
echo "  Portal:  http://${IP_SHOW}:5173"
echo "  API:     http://${IP_SHOW}:8080/readyz"
echo "  Admin:   bootstrap password from wizard"
echo "  Re-run:  rm $DONE_FLAG && systemctl start keeppam-firstboot"
echo
