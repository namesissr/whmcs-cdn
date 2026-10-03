# Pasargad CDN — example node provider: Hetzner Cloud (SPEC §23.9, docs/TERRAFORM.md).
#
# One hcloud_server per node name with the module's cloud-init. The API token comes ONLY from the
# provisioner's environment (HCLOUD_TOKEN, read by the hcloud provider) — never a variable, file or the
# controller. Server type / location come from the size / region maps below; adjust them to your account.
# Other clouds: copy this directory to providers/<name> with the same variables (docs/TERRAFORM.md).

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.48"
    }
  }
}

provider "hcloud" {}

variable "controller_url" {
  type = string
}
variable "names" {
  type = list(string)
}
variable "join_tokens" {
  type      = map(string)
  sensitive = true
}
variable "region" {
  type = string
}
variable "role" {
  type    = string
  default = "general"
}
variable "group" {
  type    = string
  default = "general"
}
variable "size" {
  type    = string
  default = "medium"
}
variable "release" {
  type    = string
  default = ""
}

variable "server_types" {
  description = "PROVISION_SIZES name -> Hetzner server type."
  type        = map(string)
  default = {
    small  = "cx22"
    medium = "cx32"
    large  = "cx42"
  }
}

variable "locations" {
  description = "Edge region -> Hetzner location. Add \"home\" only if you really have a location for it."
  type        = map(string)
  default = {
    global = "fsn1"
  }
}

variable "image" {
  type    = string
  default = "ubuntu-24.04"
}

variable "ssh_keys" {
  description = "Names/ids of SSH keys already in the Hetzner project (optional)."
  type        = list(string)
  default     = []
}

module "node" {
  source         = "../../modules/pcdn-edge-node"
  controller_url = var.controller_url
  names          = var.names
  join_tokens    = var.join_tokens
  region         = var.region
  role           = var.role
  release        = var.release
}

resource "hcloud_server" "node" {
  for_each    = toset(var.names)
  name        = each.key
  server_type = var.server_types[var.size]
  location    = var.locations[var.region]
  image       = var.image
  ssh_keys    = var.ssh_keys
  user_data   = module.node.user_data[each.key]
  labels = {
    pcdn_group  = var.group
    pcdn_region = var.region
    pcdn_role   = var.role
  }
  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }
  lifecycle {
    # user_data only matters at first boot; never replace a running node because of it
    ignore_changes = [user_data, ssh_keys, image]
  }
}

output "nodes" {
  description = "Node name -> public IPv4 (for the operator; the controller learns IPs from heartbeats)."
  value       = { for n, s in hcloud_server.node : n => s.ipv4_address }
}
