terraform {
  required_providers {
    pcdn = {
      # not on the public registry: install a local build (see README.md / docs/TERRAFORM.md)
      source = "namesissr/pcdn"
    }
  }
}

# endpoint and api_key can also come from PCDN_ENDPOINT / PCDN_API_KEY.
# The key belongs to ONE service (site); its scopes decide what Terraform may do:
# dns -> pcdn_record / pcdn_config_section, purge -> pcdn_purge (pcdn_site works with any scope).
provider "pcdn" {
  endpoint = "https://cdn-api.pasargadmizban.com"
  api_key  = var.pcdn_api_key

  # optional
  timeout_seconds = 30 # per HTTP request
  max_retries     = 8  # 429 (any request) and 5xx/network errors (idempotent requests only)
}

variable "pcdn_api_key" {
  description = "Customer API key (pcdn_...) from the WHMCS client area"
  type        = string
  sensitive   = true
}
