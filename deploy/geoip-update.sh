#!/usr/bin/env bash
# Downloads the free DB-IP "IP to Country Lite" database (CC BY 4.0, https://db-ip.com)
# into dns/geo/country.mmdb and restarts PowerDNS so it is loaded.
# Run once before enabling GeoDNS, then monthly from cron:
#   0 4 3 * * root /opt/pcdn/deploy/geoip-update.sh >> /var/log/pcdn-geoip.log 2>&1
set -euo pipefail
cd "$(dirname "$0")/.."
BASE="${DBIP_URL_BASE:-https://download.db-ip.com/free}"
DEST=dns/geo/country.mmdb
RESTART=yes
[ "${1:-}" = "--no-restart" ] && RESTART=no

ok=""
for m in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-15) -1 month" +%Y-%m)"; do
  url="$BASE/dbip-country-lite-$m.mmdb.gz"
  echo "downloading $url"
  if curl -fsSL --retry 3 -m 300 "$url" -o "$DEST.gz.tmp"; then
    gunzip -c "$DEST.gz.tmp" > "$DEST.tmp" && ok=1 && break
  fi
done
rm -f "$DEST.gz.tmp"
if [ -z "$ok" ]; then
  echo "download failed; keeping the current database" >&2
  rm -f "$DEST.tmp"; exit 1
fi
# sanity check: a real database is several MB; refuse to install a truncated file
if [ "$(stat -c %s "$DEST.tmp")" -lt 1000000 ]; then
  echo "downloaded file is too small; keeping the current database" >&2
  rm -f "$DEST.tmp"; exit 1
fi
chmod 644 "$DEST.tmp" && mv -f "$DEST.tmp" "$DEST"
echo "installed $DEST ($(stat -c %s "$DEST") bytes)"
if [ "$RESTART" = yes ] && docker compose ps --services --status running 2>/dev/null | grep -qx pdns; then
  docker compose restart pdns && echo "PowerDNS restarted"
fi
