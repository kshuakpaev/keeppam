#!/usr/bin/env bash
# Build KeepPAM Virtual Appliance disk (qcow2) via HashiCorp Packer + QEMU.
# Prerequisites on build host:
#   - HashiCorp Packer >= 1.9 (NOT /usr/sbin/packer from cracklib)
#   - QEMU/KVM (qemu-system-x86_64, qemu-img), packer plugin qemu
#   - Optional: offline bundle from scripts/keeppam-pack.sh
#
# Usage:
#   ./scripts/appliance-build.sh
#   BUNDLE=dist/keeppam-1.0.0-offline-core ./scripts/appliance-build.sh
#   PACKER_BIN=/usr/local/bin/packer ./scripts/appliance-build.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER="$(tr -d ' \n' < "$ROOT/VERSION")"
OUT="${OUT:-$ROOT/dist/appliance}"
STAGING="$ROOT/appliance/bundle-staging"
PACKER_DIR="$ROOT/appliance/packer"
PACKER_BIN="${PACKER_BIN:-}"

find_packer() {
  if [[ -n "$PACKER_BIN" && -x "$PACKER_BIN" ]]; then
    echo "$PACKER_BIN"
    return
  fi
  for c in packer packer-bin; do
    if command -v "$c" >/dev/null 2>&1; then
      local p
      p="$(command -v "$c")"
      if "$p" version 2>/dev/null | grep -qi 'Packer v'; then
        echo "$p"
        return
      fi
    fi
  done
  if [[ -x /usr/local/bin/packer ]] && /usr/local/bin/packer version 2>/dev/null | grep -qi 'Packer v'; then
    echo /usr/local/bin/packer
    return
  fi
  return 1
}

if ! PK="$(find_packer)"; then
  cat >&2 <<'EOF'
HashiCorp Packer not found (system /usr/sbin/packer is cracklib — ignore it).

Install: https://developer.hashicorp.com/packer/install
  curl -fsSL https://releases.hashicorp.com/packer/1.11.2/packer_1.11.2_linux_amd64.zip -o /tmp/packer.zip
  unzip -o /tmp/packer.zip -d /usr/local/bin
  packer plugins install github.com/hashicorp/qemu

Also need: qemu-system-x86_64, qemu-img, KVM (/dev/kvm).
EOF
  exit 1
fi

if ! command -v qemu-img >/dev/null 2>&1; then
  echo "qemu-img required (package qemu-img / qemu-utils)" >&2
  exit 1
fi

echo "== Packer: $PK $($PK version | head -1) =="
mkdir -p "$OUT" "$STAGING"
# reset staging (keep .keep)
find "$STAGING" -mindepth 1 ! -name '.keep' -exec rm -rf {} + 2>/dev/null || true

BUNDLE="${BUNDLE:-}"
if [[ -n "$BUNDLE" ]]; then
  if [[ -d "$BUNDLE" ]]; then
    echo "== stage bundle from $BUNDLE =="
    rsync -a "$BUNDLE"/ "$STAGING"/
  elif [[ -f "$BUNDLE" ]]; then
    echo "== unpack bundle $BUNDLE =="
    tmp="$(mktemp -d /tmp/keeppam-bundle.XXXXXX)"
    tar -xzf "$BUNDLE" -C "$tmp"
    inner="$(find "$tmp" -maxdepth 1 -mindepth 1 -type d | head -1)"
    rsync -a "$inner"/ "$STAGING"/
    rm -rf "$tmp"
  else
    echo "BUNDLE not found: $BUNDLE" >&2
    exit 1
  fi
  # copy appliance docs into guest tree
  mkdir -p "$STAGING/docs"
  [[ -f "$ROOT/docs/appliance-ova.txt" ]] && cp "$ROOT/docs/appliance-ova.txt" "$STAGING/docs/"
else
  echo "== no BUNDLE — image will need USB install after first boot =="
  echo "keeppam-bundle-empty" >"$STAGING/.empty"
fi

chmod +x "$ROOT/appliance/guest/"*.sh

cd "$PACKER_DIR"
"$PK" init .
QCOW_OUT="$OUT/keeppam-${VER}-appliance"
rm -rf "$QCOW_OUT"
"$PK" build \
  -var "output_directory=$QCOW_OUT" \
  -var "bundle_staging=../bundle-staging" \
  keeppam.pkr.hcl

DISK="$(find "$QCOW_OUT" -name '*.qcow2' | head -1)"
if [[ -z "$DISK" ]]; then
  echo "no qcow2 produced under $QCOW_OUT" >&2
  exit 1
fi
ln -sfn "$(basename "$(dirname "$DISK")")/$(basename "$DISK")" "$OUT/keeppam-appliance.qcow2" 2>/dev/null || \
  cp -f "$DISK" "$OUT/keeppam-appliance.qcow2"

echo
echo "OK: $DISK"
echo "Next:"
echo "  ./scripts/appliance-export-ova.sh  $DISK"
echo "  ./scripts/appliance-export-vhdx.sh $DISK"
echo "Docs: docs/appliance-ova.txt"
