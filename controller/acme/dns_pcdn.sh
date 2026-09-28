#!/usr/bin/env sh
# acme.sh DNS API hook: publishes the DNS-01 TXT record on every Pasargad CDN
# nameserver (see app/acme_hook.py). Installed to ~/.acme.sh/dnsapi/.

dns_pcdn_add() {
  fulldomain="$1"
  txtvalue="$2"
  _info "pcdn: adding TXT for $fulldomain"
  (cd /srv && python -m app.acme_hook add "$fulldomain" "$txtvalue")
}

dns_pcdn_rm() {
  fulldomain="$1"
  txtvalue="$2"
  _info "pcdn: removing TXT for $fulldomain"
  (cd /srv && python -m app.acme_hook rm "$fulldomain" "$txtvalue")
}
