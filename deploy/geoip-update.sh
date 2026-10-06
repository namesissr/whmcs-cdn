#!/usr/bin/env bash
# Builds dns/geo/country.mmdb for GeoDNS and restarts PowerDNS so it is loaded:
#   1. the free DB-IP "IP to Country Lite" database (CC BY 4.0, https://db-ip.com)
#   2. + every range RIPE NCC registered to GEO_HOME_COUNTRY (default IR): DB-IP puts
#      part of them in other countries, which sent those visitors to foreign edges
#   3. + dns/geo/overrides.txt ("CIDR CC" lines) if present
# (deploy/geoip-build.py, python3 stdlib only). Run on EVERY nameserver (ns1 and ns2)
# once before enabling GeoDNS, then weekly from cron:
#   0 4 * * 1 root /opt/pcdn/deploy/geoip-update.sh >> /var/log/pcdn-geoip.log 2>&1
set -euo pipefail
cd "$(dirname "$0")/.."
BASE="${DBIP_URL_BASE:-https://download.db-ip.com/free}"
RIPE_URL="${RIPE_URL:-https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest}"
COUNTRY="${GEO_HOME_COUNTRY:-IR}"
COUNTRY="${COUNTRY%%,*}"
DEST=dns/geo/country.mmdb
WORK=dns/geo/build.tmp
RESTART=yes
[ "${1:-}" = "--no-restart" ] && RESTART=no

ok=""
for m in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-15) -1 month" +%Y-%m)"; do
  url="$BASE/dbip-country-lite-$m.mmdb.gz"
  echo "downloading $url"
  if curl -fsSL --retry 3 -m 300 "$url" -o "$WORK.gz"; then
    gunzip -c "$WORK.gz" > "$WORK.dbip" && ok=1 && break
  fi
done
rm -f "$WORK.gz"
if [ -z "$ok" ]; then
  echo "download failed; keeping the current database" >&2
  rm -f "$WORK".*; exit 1
fi
# sanity check: a real database is several MB; refuse to use a truncated file
if [ "$(stat -c %s "$WORK.dbip")" -lt 1000000 ]; then
  echo "downloaded file is too small; keeping the current database" >&2
  rm -f "$WORK".*; exit 1
fi

args=(--dbip "$WORK.dbip" --country "$COUNTRY" --out "$WORK.mmdb")
echo "downloading $RIPE_URL"
if curl -fsSL --retry 3 -m 300 "$RIPE_URL" -o "$WORK.ripe" && [ "$(grep -c "|$COUNTRY|ipv4|" "$WORK.ripe")" -gt 100 ]; then
  args+=(--ripe "$WORK.ripe")
else
  echo "WARNING: RIPE registrations unavailable; using DB-IP alone (less accurate for $COUNTRY)" >&2
fi
[ -s dns/geo/overrides.txt ] && args+=(--overrides dns/geo/overrides.txt)
[ "$COUNTRY" = IR ] && args+=(--expect 2.176.0.1=IR --expect 5.160.0.1=IR --expect 8.8.8.8=US)
if python3 deploy/geoip-build.py "${args[@]}"; then
  mv -f "$WORK.mmdb" "$DEST.tmp"
else
  echo "WARNING: building the corrected database failed; installing plain DB-IP" >&2
  mv -f "$WORK.dbip" "$DEST.tmp"
fi
rm -f "$WORK".*
chmod 644 "$DEST.tmp" && mv -f "$DEST.tmp" "$DEST"
echo "installed $DEST ($(stat -c %s "$DEST") bytes)"
if [ "$RESTART" = yes ]; then
  # the panel's pdns (docker-compose.yml) or a standalone ns2 (deploy/ns2-compose.yml)
  ids=$(docker ps -q --filter label=com.docker.compose.service=pdns 2>/dev/null || true)
  if [ -n "$ids" ]; then
    docker restart $ids >/dev/null && echo "PowerDNS restarted"
  fi
fi
