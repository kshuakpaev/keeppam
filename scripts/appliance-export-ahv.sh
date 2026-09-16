#!/usr/bin/env bash
# Stage qcow2 + Nutanix AHV import notes (nit2 2.3).
# Usage: ./scripts/appliance-export-ahv.sh [path/to/disk.qcow2]
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
mkdir -p "$OUT_DIR"
cp -f "$IN" "$OUT_DIR/${NAME}.qcow2"
cat > "$OUT_DIR/${NAME}-ahv.txt" <<EOF
KeepPAM ${VER} — импорт в Nutanix AHV

Готовый сертифицированный AHV image от Nutanix не поставляется: используется тот же
гостевой диск Ubuntu 24.04 + Docker, что и для KVM/Proxmox (qcow2).

Prism / acli (пример):

  # Image
  acli image.create keeppam-${VER} image_type=DISK_IMAGE source_url=file://${NAME}.qcow2 container=<CTR>

  # VM
  acli vm.create KeepPAM memory=8G num_vcpus=4
  acli vm.disk_create KeepPAM clone_from_image=keeppam-${VER}
  acli vm.nic_create KeepPAM network=<VLAN>
  acli vm.on KeepPAM

Консоль → first-boot wizard (docs/appliance-ova.txt). Портал http://<ip>:5173
EOF
echo "wrote $OUT_DIR/${NAME}.qcow2"
echo "wrote $OUT_DIR/${NAME}-ahv.txt"
