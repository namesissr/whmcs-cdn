# Pasargad CDN — FAKE node provider (tests and CI `terraform validate`; no cloud, SPEC §23.9).
#
# Same variables as every providers/<name> directory. Instead of servers it creates one terraform_data
# per node and writes each node's cloud-init to <output_dir>/<name>.cloud-init.yaml (0600), so the
# provisioner flow (plan -> summary -> apply) can be exercised end to end without credentials.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

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
variable "output_dir" {
  description = "Where the fake nodes' cloud-init files are written."
  type        = string
  default     = "out"
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

resource "terraform_data" "node" {
  for_each = toset(var.names)
  input = {
    name   = each.key
    group  = var.group
    region = var.region
    size   = var.size
  }
}

resource "local_sensitive_file" "user_data" {
  for_each        = toset(var.names)
  filename        = "${var.output_dir}/${each.key}.cloud-init.yaml"
  content         = module.node.user_data[each.key]
  file_permission = "0600"
}

output "nodes" {
  value = { for n in var.names : n => terraform_data.node[n].id }
}
