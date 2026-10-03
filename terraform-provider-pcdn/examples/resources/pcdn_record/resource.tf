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

# Weighted set with HTTP(S) probes by the controller (SPEC §16.7): 70/30 split, unhealthy members are
# withdrawn from the answer (never all of them). health_path defaults to "/" for http/https.
resource "pcdn_record" "app_a" {
  name            = "app"
  type            = "A"
  content         = "185.1.2.20"
  weight          = 70
  health_check    = true
  health_protocol = "https"
  health_path     = "/healthz"
}

resource "pcdn_record" "app_b" {
  name            = "app"
  type            = "A"
  content         = "185.1.2.21"
  weight          = 30
  health_check    = true
  health_protocol = "https"
}
