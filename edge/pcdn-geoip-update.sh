#!/usr/bin/env bash
# Pasargad CDN — refresh the DB-IP "IP to Country Lite" database (CC BY 4.0, monthly).
# Installed as /usr/local/sbin/pcdn-geoip-update and run by pcdn-geoip.timer.
#   --asn         the DB-IP "IP to ASN Lite" database instead (CC BY 4.0), used only for the coarse ISP
#                 breakdown of RUM reports (SPEC §23.7; agent.conf RUM_ASN_DB, default
#                 /usr/share/pcdn/geo/asn.mmdb). Never used for node selection or DNS.
#   --if-missing  do nothing when the database file already exists (daily retry timer)
#
# nginx's geoip2 module reloads the file by itself (auto_reload); when the database
# appears for the first time pcdn-agent notices and re-renders http.conf with it.
set -euo pipefail

KIND=country
IF_MISSING=no
for arg in "$@"; do
  case "$arg" in
    --asn) KIND=asn ;;
    --if-missing) IF_MISSING=yes ;;
    *) echo "pcdn-geoip-update: unknown option $arg" >&2; exit 2 ;;
  esac
done
if [ "$KIND" = asn ]; then
  DEST="${PCDN_ASN_DB:-/usr/share/pcdn/geo/asn.mmdb}"
  NAME=dbip-asn-lite
  MIN_SIZE=200000
else
  DEST="${PCDN_GEOIP_DB:-/usr/share/pcdn/geo/country.mmdb}"
  NAME=dbip-country-lite
  MIN_SIZE=1000000
fi
BASE="${PCDN_GEOIP_URL:-https://download.db-ip.com/free}"

# F9: the daily retry timer runs with --if-missing and must be a cheap no-op once the DB exists, so
# it does not re-download monthly-stable data every day (the monthly timer handles the refresh).
if [ "$IF_MISSING" = yes ] && [ -s "$DEST" ]; then
  echo "pcdn-geoip-update: $DEST already present, skipping"
  exit 0
fi

DIR="$(dirname "$DEST")"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$DIR"

ok=no
# the new month's file is published during the first days of the month: fall back to last month
for month in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m)"; do
  if curl -fsSL --retry 3 --max-time 300 -o "$TMP/db.mmdb.gz" "$BASE/$NAME-$month.mmdb.gz"; then
    ok=yes
    break
  fi
done
[ "$ok" = yes ] || { echo "pcdn-geoip-update: download failed" >&2; exit 1; }

gzip -dc "$TMP/db.mmdb.gz" > "$TMP/db.mmdb"
# sanity: a real database is several MB and carries the MaxMind DB metadata marker
size="$(stat -c %s "$TMP/db.mmdb")"
if [ "$size" -lt "$MIN_SIZE" ] || ! grep -q "MaxMind.com" "$TMP/db.mmdb"; then
  echo "pcdn-geoip-update: downloaded file does not look like an mmdb database" >&2
  exit 1
fi
chmod 644 "$TMP/db.mmdb"
mv -f "$TMP/db.mmdb" "$DEST.new"
mv -f "$DEST.new" "$DEST"
echo "pcdn-geoip-update: installed $DEST ($size bytes)"
