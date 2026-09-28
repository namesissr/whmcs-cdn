#!/usr/bin/env bash
# Pasargad CDN — refresh the DB-IP "IP to Country Lite" database (CC BY 4.0, monthly).
# Installed as /usr/local/sbin/pcdn-geoip-update and run by pcdn-geoip.timer.
#
# nginx's geoip2 module reloads the file by itself (auto_reload); when the database
# appears for the first time pcdn-agent notices and re-renders http.conf with it.
set -euo pipefail

DEST="${PCDN_GEOIP_DB:-/usr/share/pcdn/geo/country.mmdb}"
BASE="${PCDN_GEOIP_URL:-https://download.db-ip.com/free}"
DIR="$(dirname "$DEST")"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$DIR"

ok=no
# the new month's file is published during the first days of the month: fall back to last month
for month in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m)"; do
  if curl -fsSL --retry 3 --max-time 300 -o "$TMP/db.mmdb.gz" "$BASE/dbip-country-lite-$month.mmdb.gz"; then
    ok=yes
    break
  fi
done
[ "$ok" = yes ] || { echo "pcdn-geoip-update: download failed" >&2; exit 1; }

gzip -dc "$TMP/db.mmdb.gz" > "$TMP/db.mmdb"
# sanity: a real database is several MB and carries the MaxMind DB metadata marker
size="$(stat -c %s "$TMP/db.mmdb")"
if [ "$size" -lt 1000000 ] || ! grep -q "MaxMind.com" "$TMP/db.mmdb"; then
  echo "pcdn-geoip-update: downloaded file does not look like an mmdb database" >&2
  exit 1
fi
chmod 644 "$TMP/db.mmdb"
mv -f "$TMP/db.mmdb" "$DEST.new"
mv -f "$DEST.new" "$DEST"
echo "pcdn-geoip-update: installed $DEST ($size bytes)"
