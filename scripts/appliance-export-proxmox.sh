#!/usr/bin/env bash
# Stage qcow2 + Proxmox import notes (nit2 2.3).
# Usage: ./scripts/appliance-export-proxmox.sh [path/to/disk.qcow2]
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
cat > "$OUT_DIR/${NAME}-proxmox.txt" <<EOF
KeepPAM ${VER} — импорт в Proxmox VE

1. Загрузить диск:
   scp ${NAME}.qcow2 root@pve:/var/lib/vz/template/qemu/

2. Создать VM (пример: id 800, 4 CPU, 8 GiB RAM, UEFI):
   qm create 800 --name KeepPAM --memory 8192 --cores 4 --net0 virtio,bridge=vmbr0 --bios ovmf --scsihw virtio-scsi-pci
   qm importdisk 800 /var/lib/vz/template/qemu/${NAME}.qcow2 local-lvm
   qm set 800 --scsi0 local-lvm:vm-800-disk-0 --boot order=scsi0 --agent enabled=1

3. Start → консоль → first-boot wizard (docs/appliance-ova.txt).
   Портал http://<ip>:5173
EOF
echo "wrote $OUT_DIR/${NAME}.qcow2"
echo "wrote $OUT_DIR/${NAME}-proxmox.txt"
