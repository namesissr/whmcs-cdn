data "pcdn_site" "this" {}

output "domain" {
  value = data.pcdn_site.this.domain
}

output "nameservers" {
  value = data.pcdn_site.this.nameservers
}

output "waf_in_plan" {
  value = jsondecode(data.pcdn_site.this.plan_json).features.waf
}
