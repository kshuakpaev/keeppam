packer {
  required_version = ">= 1.9.0"
  required_plugins {
    qemu = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "ubuntu_cloud_img" {
  type        = string
  description = "URL or local path to Ubuntu 24.04 server cloudimg (qcow2)"
  default     = "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
}

variable "ubuntu_cloud_checksum" {
  type    = string
  default = "file:https://cloud-images.ubuntu.com/releases/24.04/release/SHA256SUMS"
}

variable "disk_size" {
  type    = string
  default = "80G"
}

variable "cpus" {
  type    = number
  default = 4
}

variable "memory" {
  type    = number
  default = 8192
}

variable "ssh_password" {
  type    = string
  default = "keeppam"
}

variable "output_directory" {
  type    = string
  default = "output-keeppam-appliance"
}

# Always present: scripts/appliance-build.sh fills this from offline bundle or leaves .keep
variable "bundle_staging" {
  type    = string
  default = "../bundle-staging"
}

source "qemu" "keeppam" {
  iso_url      = var.ubuntu_cloud_img
  iso_checksum = var.ubuntu_cloud_checksum
  disk_image   = true

  output_directory = var.output_directory
  vm_name          = "keeppam-appliance"
  format           = "qcow2"
  disk_size        = var.disk_size
  disk_interface   = "virtio"
  net_device       = "virtio-net"
  accelerator      = "kvm"

  cpus     = var.cpus
  memory   = var.memory
  headless = true

  ssh_username = "keeppam"
  ssh_password = var.ssh_password
  ssh_timeout  = "30m"

  http_directory = "${path.root}/http"
  cd_files = [
    "${path.root}/http/user-data",
    "${path.root}/http/meta-data",
  ]
  cd_label = "cidata"

  shutdown_command = "echo '${var.ssh_password}' | sudo -S shutdown -P now"
  boot_wait        = "10s"
}

build {
  name    = "keeppam-appliance"
  sources = ["source.qemu.keeppam"]

  provisioner "file" {
    source      = "${path.root}/../guest/keeppam-firstboot.sh"
    destination = "/tmp/keeppam-firstboot.sh"
  }

  provisioner "file" {
    source      = "${path.root}/../guest/keeppam-firstboot.service"
    destination = "/tmp/keeppam-firstboot.service"
  }

  provisioner "file" {
    source      = "${path.root}/../guest/install-guest.sh"
    destination = "/tmp/install-guest.sh"
  }

  provisioner "file" {
    source      = "${path.root}/${var.bundle_staging}/"
    destination = "/tmp/keeppam-bundle"
  }

  provisioner "shell" {
    inline = [
      "chmod +x /tmp/install-guest.sh /tmp/keeppam-firstboot.sh",
      "echo '${var.ssh_password}' | sudo -S bash /tmp/install-guest.sh",
      "if [ -f /tmp/keeppam-bundle/deploy/docker-compose.yml ] || [ -f /tmp/keeppam-bundle/images.tar ]; then echo '${var.ssh_password}' | sudo -S rsync -a /tmp/keeppam-bundle/ /opt/keeppam/; echo '${var.ssh_password}' | sudo -S bash -c '[[ -f /opt/keeppam/images.tar ]] && docker load -i /opt/keeppam/images.tar || true'; fi",
      "echo '${var.ssh_password}' | sudo -S cloud-init clean --logs || true",
      "echo '${var.ssh_password}' | sudo -S rm -f /var/lib/keeppam/firstboot.done",
    ]
  }

  post-processor "manifest" {
    output     = "${var.output_directory}/packer-manifest.json"
    strip_path = true
  }
}
