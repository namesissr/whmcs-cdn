# The whole section is replaced on every apply: keys left out get the controller's defaults.
resource "pcdn_config_section" "cache" {
  section = "cache"
  config = jsonencode({
    enabled        = true
    level          = "standard"
    edge_ttl       = 86400
    browser_ttl    = 0
    bypass_cookies = ["wordpress_logged_in", "PHPSESSID"]
    always_online  = true
  })
}

resource "pcdn_config_section" "firewall" {
  section = "firewall"
  config = jsonencode({
    default_action = "allow"
    rules = [
      {
        id         = "block-countries"
        name       = "Block some countries"
        enabled    = true
        action     = "block"
        conditions = [{ field = "country", op = "in", value = ["CN", "RU"] }]
      },
      {
        id         = "challenge-admin"
        action     = "challenge"
        conditions = [{ field = "path", op = "starts_with", value = "/wp-admin" }]
      },
    ]
  })
}

# Log export with a write-only secret: the controller never returns secret_key, the provider keeps
# the configured value in state and never shows a diff for it.
variable "logs_access_key" {
  type = string
}

variable "logs_secret_key" {
  type      = string
  sensitive = true
}

resource "pcdn_config_section" "logs" {
  section = "logs"
  config = jsonencode({
    enabled      = true
    s3_endpoint  = "https://s3.example.net"
    region       = "us-east-1"
    bucket       = "cdn-logs"
    prefix       = "pcdn/"
    access_key   = var.logs_access_key
    secret_key   = var.logs_secret_key
    anonymize_ip = true
    sample_rate  = 0.1
  })
}

# Webhooks: the controller assigns ids and returns each signing secret once; the provider keeps
# them in the sensitive `secrets` map (keyed by webhook id).
resource "pcdn_config_section" "webhooks" {
  section = "webhooks"
  config = jsonencode({
    items = [{
      url    = "https://hooks.example.com/pcdn"
      events = ["purge.completed", "ssl.failed", "quota.warning"]
    }]
  })
}

output "webhook_ids" {
  value = [for h in jsondecode(pcdn_config_section.webhooks.result).items : h.id]
}

output "webhook_secrets" {
  value     = pcdn_config_section.webhooks.secrets
  sensitive = true
}
