#!/usr/bin/env bash
# Provisioning step for Packer: install Docker, copy KeepPAM tree, enable first-boot.
# Runs as root inside the guest during image build.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg lsb-release net-tools rsync \
  openssh-server qemu-guest-agent cloud-init open-vm-tools

# Docker CE
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    >/etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi

systemctl enable docker
usermod -aG docker keeppam 2>/dev/null || true
systemctl enable qemu-guest-agent 2>/dev/null || true
systemctl enable open-vm-tools 2>/dev/null || true
systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true

install -d -m 0755 /opt/keeppam /usr/local/sbin /var/lib/keeppam
install -m 0755 /tmp/keeppam-firstboot.sh /usr/local/sbin/keeppam-firstboot
install -m 0644 /tmp/keeppam-firstboot.service /etc/systemd/system/keeppam-firstboot.service
systemctl daemon-reload
systemctl enable keeppam-firstboot.service

# Optional: offline bundle placed by Packer provisioner into /tmp/keeppam-bundle
if [[ -d /tmp/keeppam-bundle ]]; then
  echo "Installing KeepPAM tree from /tmp/keeppam-bundle → /opt/keeppam"
  rsync -a --delete /tmp/keeppam-bundle/ /opt/keeppam/
  chmod +x /opt/keeppam/scripts/*.sh 2>/dev/null || true
  chmod +x /opt/keeppam/install.sh 2>/dev/null || true
  if [[ -f /opt/keeppam/images.tar ]]; then
    echo "docker load images.tar (may take several minutes)…"
    docker load -i /opt/keeppam/images.tar
  fi
fi

# Motd
cat >/etc/motd <<'EOF'
KeepPAM Virtual Appliance
  First boot wizard runs once on tty1 (keeppam-firstboot).
  Portal default port: 5173  ·  API: 8080
  Docs: /opt/keeppam/docs/appliance-ova.txt
EOF

# Disable cloud-init network if we manage netplan ourselves after first boot
mkdir -p /etc/cloud/cloud.cfg.d
printf 'network: {config: disabled}\n' >/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg

apt-get clean
rm -rf /var/lib/apt/lists/*
echo "guest provision done"
