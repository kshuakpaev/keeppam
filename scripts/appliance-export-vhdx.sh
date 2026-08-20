#!/usr/bin/env bash
# Convert appliance qcow2 → VHDX for Hyper-V Generation 2.
# Usage: ./scripts/appliance-export-vhdx.sh [path/to/disk.qcow2]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER="$(tr -d ' \n' < "$ROOT/VERSION")"
IN="${1:-$ROOT/dist/appliance/keeppam-appliance.qcow2}"
OUT_DIR="${OUT:-$ROOT/dist/appliance}"
NAME="keeppam-${VER}"

if [[ ! -f "$IN" ]]; then
  echo "disk not found: $IN (run appliance-build.sh first)" >&2
  exit 1
fi
if ! command -v qemu-img >/dev/null 2>&1; then
  echo "qemu-img required" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
VHDX="$OUT_DIR/${NAME}.vhdx"
echo "== qemu-img convert → VHDX =="
qemu-img convert -f qcow2 -O vhdx -o subformat=dynamic "$IN" "$VHDX"
sha256sum "$VHDX" | tee "$VHDX.sha256"

cat >"$OUT_DIR/${NAME}-hyperv.txt" <<EOF
KeepPAM Hyper-V import (Generation 2)

1. Copy ${NAME}.vhdx to the Hyper-V host.
2. New-VM -Name KeepPAM -Generation 2 -MemoryStartupBytes 8GB -VHDPath .\\${NAME}.vhdx
3. Set-VMProcessor KeepPAM -Count 4
4. Enable Secure Boot: template Microsoft UEFI Certificate Authority (Ubuntu).
   Or: Set-VMFirmware KeepPAM -EnableSecureBoot Off  (lab only)
5. Connect external/internal switch; Start-VM KeepPAM
6. Open console → first-boot wizard (hostname, IP, admin password).
7. Portal http://<ip>:5173

Guest tools: open-vm-tools is for VMware; on Hyper-V install linux-azure /
  hyperv-daemons inside the guest after first boot if needed.
EOF

echo
echo "OK: $VHDX"
echo "Notes: $OUT_DIR/${NAME}-hyperv.txt"
