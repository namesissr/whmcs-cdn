#!/usr/bin/env bash
# Pasargad CDN — edge node installer (Ubuntu 24.04 LTS)
#
#   sudo ./install.sh --controller https://cdn-api.pasargadmizban.com --token edge_xxxxx
#
# Uses the distribution nginx (1.24) with the distro dynamic modules:
#   libnginx-mod-http-js (njs >= 0.8.1), -geoip2, -image-filter, -brotli-filter
#
# Options:
#   --no-ipv6          do not listen on IPv6
#   --cache-size 50g   max disk used by the cache of each site (default 10g)
#   --http-port N      public HTTP port (default 80)
#   --https-port N     public HTTPS port (default 443)
#   --no-geoip         do not download the DB-IP country database (country rules never match)
#   --distro-nginx     accepted for compatibility (the distro nginx is always used now)
set -euo pipefail

CONTROLLER=""
TOKEN=""
IPV6=yes
CACHE_SIZE=10g
HTTP_PORT=80
HTTPS_PORT=443
GEOIP=yes
HERE="$(cd "$(dirname "$0")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --controller) CONTROLLER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --no-ipv6) IPV6=no; shift ;;
    --distro-nginx) shift ;;
    --cache-size) CACHE_SIZE="$2"; shift 2 ;;
    --http-port) HTTP_PORT="$2"; shift 2 ;;
    --https-port) HTTPS_PORT="$2"; shift 2 ;;
    --no-geoip) GEOIP=no; shift ;;
    *) echo "unknown option: $1"; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
[ -n "$CONTROLLER" ] && [ -n "$TOKEN" ] || { echo "usage: $0 --controller URL --token TOKEN"; exit 1; }
[ -f /etc/debian_version ] || { echo "only Ubuntu 24.04 (or a Debian derivative with njs >= 0.8.1) is supported"; exit 1; }
case "$HTTP_PORT$HTTPS_PORT" in *[!0-9]*) echo "ports must be numeric"; exit 1 ;; esac
. /etc/os-release
if [ "${ID:-}" != ubuntu ] || [ "${VERSION_ID%%.*}" -lt 24 ]; then
  echo "warning: tested on Ubuntu 24.04; continuing on ${PRETTY_NAME:-unknown}"
fi

echo "==> packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q curl ca-certificates python3 logrotate gzip \
  nginx libnginx-mod-http-js libnginx-mod-http-geoip2 libnginx-mod-http-image-filter libnginx-mod-http-brotli-filter

# js_periodic / js_shared_dict_zone need njs >= 0.8.1
NJS_VER="$(dpkg-query -W -f='${Version}' libnginx-mod-http-js 2>/dev/null | sed 's/^[0-9]*://; s/-.*//')"
if ! printf '0.8.1\n%s\n' "$NJS_VER" | sort -V -C; then
  echo "njs $NJS_VER is too old (need >= 0.8.1)"; exit 1
fi
# an old install may have pinned nginx.org packages; the distro build carries the modules we need
rm -f /etc/apt/sources.list.d/nginx.list /etc/apt/preferences.d/99nginx

NGINX_USER="$(awk '/^[[:space:]]*user[[:space:]]/{gsub(";","",$2); print $2; exit}' /etc/nginx/nginx.conf)"
NGINX_USER="${NGINX_USER:-www-data}"

echo "==> files"
install -d -m 755 /etc/pcdn /var/lib/pcdn /usr/share/pcdn/pages /usr/share/pcdn/njs /usr/share/pcdn/nginx /usr/share/pcdn/geo
install -d -m 755 -o "$NGINX_USER" /var/cache/pcdn
install -m 755 "$HERE/pcdn-agent.py" /usr/local/bin/pcdn-agent
install -m 644 "$HERE"/pages/*.html /usr/share/pcdn/pages/
install -m 644 "$HERE/njs/pcdn.js" /usr/share/pcdn/njs/pcdn.js
install -m 644 "$HERE/nginx/pcdn-base.conf" /usr/share/pcdn/nginx/pcdn-base.conf
install -m 644 "$HERE/systemd/pcdn-agent.service" /etc/systemd/system/pcdn-agent.service
install -m 644 "$HERE/systemd/pcdn-geoip.service" /etc/systemd/system/pcdn-geoip.service
install -m 644 "$HERE/systemd/pcdn-geoip.timer" /etc/systemd/system/pcdn-geoip.timer
install -m 755 "$HERE/pcdn-geoip-update.sh" /usr/local/sbin/pcdn-geoip-update
# the agent renders /etc/nginx/pcdn/http.conf (base config) + sites; conf.d only includes it
echo 'include /etc/nginx/pcdn/http.conf;' > /etc/nginx/conf.d/00-pcdn.conf
rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf

# directives that our http.conf sets would be "duplicate" next to the stock nginx.conf ones
sed -i -E 's/^([[:space:]]*)(gzip[[:space:]]+on;|ssl_protocols[[:space:]]|ssl_prefer_server_ciphers[[:space:]])/\1# pcdn (set in pcdn http.conf): \2/' /etc/nginx/nginx.conf
# more connections / open files than the stock config
sed -i 's/^\([[:space:]]*worker_connections\).*/\1 16384;/' /etc/nginx/nginx.conf
grep -q '^worker_rlimit_nofile' /etc/nginx/nginx.conf || sed -i '1i worker_rlimit_nofile 200000;' /etc/nginx/nginx.conf

umask 077
cat > /etc/pcdn/agent.conf <<EOF
CONTROLLER_URL=$CONTROLLER
EDGE_TOKEN=$TOKEN
NGINX_USER=$NGINX_USER
LISTEN_IPV6=$IPV6
CACHE_MAX_SIZE=$CACHE_SIZE
HTTP_PORT=$HTTP_PORT
HTTPS_PORT=$HTTPS_PORT
GEOIP_DB=/usr/share/pcdn/geo/country.mmdb
NGINX_TEST_CMD=nginx -t -q
NGINX_RELOAD_CMD=systemctl reload nginx
EOF
umask 022

cat > /etc/logrotate.d/pcdn <<'EOF'
/var/log/nginx/pcdn-access.log {
    daily
    rotate 3
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        [ -s /run/nginx.pid ] && kill -USR1 "$(cat /run/nginx.pid)" || true
    endscript
}
EOF

cat > /etc/sysctl.d/99-pcdn.conf <<'EOF'
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
fs.file-max = 1000000
EOF
sysctl --system >/dev/null 2>&1 || true

echo "==> GeoIP (DB-IP IP to Country Lite, CC BY 4.0)"
systemctl daemon-reload
if [ "$GEOIP" = yes ]; then
  /usr/local/sbin/pcdn-geoip-update || echo "warning: GeoIP download failed; the monthly timer will retry"
  systemctl enable --now pcdn-geoip.timer
fi

echo "==> services"
# an empty tree first so nginx can start before the agent's first sync
PCDN_CONFIG=/etc/pcdn/agent.conf /usr/bin/python3 /usr/local/bin/pcdn-agent bootstrap
nginx -t
systemctl enable --now nginx
systemctl reload nginx
PCDN_CONFIG=/etc/pcdn/agent.conf /usr/bin/python3 /usr/local/bin/pcdn-agent once </dev/null || true
systemctl enable --now pcdn-agent

echo
echo "Edge installed. Check: systemctl status pcdn-agent ; journalctl -u pcdn-agent -f"
echo "Health: curl -H 'Host: health.pcdn' http://127.0.0.1:$HTTP_PORT/__pcdn/health"
