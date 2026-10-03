# Pasargad CDN — provider-agnostic edge node bootstrap (SPEC §23.9, docs/TERRAFORM.md)
#
# Pure module (no resources): for every node name it renders the cloud-init user_data that installs the
# edge with a ONE-TIME join token (PCDN_JOIN_TOKEN env + bootstrap.sh, frozen contract SPEC §23.18 #8):
#
#   curl -fsSL --proto '=https' <controller>/edge/bootstrap.sh |
#     PCDN_JOIN_TOKEN=<token> bash -s -- --controller <url> --role <role> --region <region> [--version <release>]
#
# Join tokens are single use and expire after JOIN_TOKEN_HOURS (default 24): once the node has joined the
# copy in the cloud provider's metadata / Terraform state is worthless. Cloud credentials never pass
# through this module.

terraform {
  required_version = ">= 1.5.0"
}

variable "controller_url" {
  description = "Public controller URL (https://…), as served to nodes."
  type        = string
  validation {
    condition     = can(regex("^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$", var.controller_url))
    error_message = "controller_url must be https://host[:port]."
  }
}

variable "names" {
  description = "Node names (the Edge rows the controller created for the proposal)."
  type        = list(string)
  validation {
    condition     = length(var.names) > 0 && alltrue([for n in var.names : can(regex("^[a-z0-9][a-z0-9-]{0,62}$", n))])
    error_message = "names must be 1..n lower-case DNS labels."
  }
}

variable "join_tokens" {
  description = "Map node name -> one-time join token (jt_ + 40 hex)."
  type        = map(string)
  sensitive   = true
  validation {
    condition     = alltrue([for t in values(var.join_tokens) : can(regex("^jt_[0-9a-f]{40}$", t))])
    error_message = "every join token must be jt_ followed by 40 hex characters."
  }
}

variable "region" {
  description = "Edge region: home or global."
  type        = string
  validation {
    condition     = contains(["home", "global"], var.region)
    error_message = "region must be home or global."
  }
}

variable "role" {
  description = "Edge role / group: general or tunnel."
  type        = string
  default     = "general"
  validation {
    condition     = contains(["general", "tunnel"], var.role)
    error_message = "role must be general or tunnel."
  }
}

variable "release" {
  description = "Pinned edge release vX.Y.Z to install (empty = the controller's pin or live bundle)."
  type        = string
  default     = ""
  validation {
    condition     = var.release == "" || can(regex("^v[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?$", var.release))
    error_message = "release must be empty or vX.Y.Z[-pre]."
  }
}

locals {
  base    = trimsuffix(var.controller_url, "/")
  version = var.release == "" ? "" : " --version ${var.release}"
  user_data = {
    for n in var.names : n => join("\n", [
      "#cloud-config",
      "# Pasargad CDN edge node ${n} (one-time join token; SPEC §23.9)",
      "package_update: true",
      "packages: [curl, ca-certificates]",
      "runcmd:",
      "  - [bash, -c, \"set -o pipefail; curl -fsSL --proto '=https' ${local.base}/edge/bootstrap.sh | PCDN_JOIN_TOKEN=${var.join_tokens[n]} bash -s -- --controller ${local.base} --role ${var.role} --region ${var.region}${local.version}\"]",
      "",
    ])
  }
}

output "user_data" {
  description = "Map node name -> cloud-init user_data (contains the one-time join token)."
  value       = local.user_data
  sensitive   = true
}

output "names" {
  description = "The node names, in order."
  value       = var.names
}
