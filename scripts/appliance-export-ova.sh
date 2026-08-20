#!/usr/bin/env bash
# Convert appliance qcow2 → streamOptimized VMDK + OVF → .ova (VMware).
# Usage: ./scripts/appliance-export-ova.sh [path/to/disk.qcow2]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER="$(tr -d ' \n' < "$ROOT/VERSION")"
IN="${1:-$ROOT/dist/appliance/keeppam-appliance.qcow2}"
OUT_DIR="${OUT:-$ROOT/dist/appliance}"
NAME="keeppam-${VER}"
CPUS="${CPUS:-4}"
MEMORY_MB="${MEMORY_MB:-8192}"

if [[ ! -f "$IN" ]]; then
  echo "disk not found: $IN (run appliance-build.sh first)" >&2
  exit 1
fi
if ! command -v qemu-img >/dev/null 2>&1; then
  echo "qemu-img required" >&2
  exit 1
fi

STAGE="$(mktemp -d /tmp/keeppam-ova.XXXXXX)"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

VMDK="$STAGE/${NAME}-disk1.vmdk"
echo "== qemu-img convert → VMDK (streamOptimized) =="
qemu-img convert -f qcow2 -O vmdk -o subformat=streamOptimized "$IN" "$VMDK"
SIZE_BYTES="$(stat -c%s "$VMDK" 2>/dev/null || stat -f%z "$VMDK")"

OVF="$STAGE/${NAME}.ovf"
sed -e "s/{{NAME}}/${NAME}/g" \
    -e "s/{{DISK}}/${NAME}-disk1.vmdk/g" \
    -e "s/{{SIZE_BYTES}}/${SIZE_BYTES}/g" \
    -e "s/{{CPUS}}/${CPUS}/g" \
    -e "s/{{MEMORY_MB}}/${MEMORY_MB}/g" \
    -e "s/{{VERSION}}/${VER}/g" \
    "$ROOT/appliance/ovf/keeppam.ovf.template" >"$OVF"

MF="$STAGE/${NAME}.mf"
{
  echo "SHA256(${NAME}.ovf)= $(sha256sum "$OVF" | awk '{print $1}')"
  echo "SHA256(${NAME}-disk1.vmdk)= $(sha256sum "$VMDK" | awk '{print $1}')"
} >"$MF"

mkdir -p "$OUT_DIR"
OVA="$OUT_DIR/${NAME}.ova"
echo "== tar → $OVA =="
tar -C "$STAGE" -cvf "$OVA" "${NAME}.ovf" "${NAME}-disk1.vmdk" "${NAME}.mf"
sha256sum "$OVA" | tee "$OVA.sha256"

echo
echo "Import in vSphere / ESXi / Workstation: File → Deploy OVF / Import $OVA"
echo "After power-on: console first-boot wizard (tty1)."
