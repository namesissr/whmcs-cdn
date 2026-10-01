# Apex served through the CDN.
resource "pcdn_record" "apex" {
  name    = "@"
  type    = "A"
  content = "185.1.2.3"
  proxied = true
}

# www -> apex, proxied, origin on a custom port.
resource "pcdn_record" "www" {
  name        = "www"
  type        = "CNAME"
  content     = "example.com"
  proxied     = true
  origin_port = 8080
}

# DNS-only records.
resource "pcdn_record" "mail" {
  name     = "@"
  type     = "MX"
  content  = "mail.example.com"
  priority = 10
}

resource "pcdn_record" "spf" {
  type    = "TXT"
  content = "v=spf1 mx -all"
  ttl     = 3600
}

# DNS failover between origins: only addresses whose TCP port answers are returned.
resource "pcdn_record" "origin_a" {
  name         = "origin"
  type         = "A"
  content      = "185.1.2.10"
  health_check = true
  health_port  = 443
}

resource "pcdn_record" "origin_b" {
  name         = "origin"
  type         = "A"
  content      = "185.1.2.11"
  health_check = true
  health_port  = 443
}
