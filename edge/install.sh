#!/usr/bin/env bash
# Pasargad CDN — edge node installer (Debian 11+/Ubuntu 22.04+)
#
#   sudo ./install.sh --controller https://cdn-api.pasargadmizban.com --token edge_xxxxx
#
# Options:
#   --no-ipv6        do not listen on IPv6
#   --distro-nginx   use the distribution's nginx instead of the nginx.org stable repo
#   --cache-size 50g max disk used by the cache of each site (default 10g)
set -euo pipefail

CONTROLLER=""
TOKEN=""
IPV6=yes
DISTRO_NGINX=no
CACHE_SIZE=10g
HERE="$(cd "$(dirname "$0")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --controller) CONTROLLER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --no-ipv6) IPV6=no; shift ;;
    --distro-nginx) DISTRO_NGINX=yes; shift ;;
    --cache-size) CACHE_SIZE="$2"; shift 2 ;;
    *) echo "unknown option: $1"; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
[ -n "$CONTROLLER" ] && [ -n "$TOKEN" ] || { echo "usage: $0 --controller URL --token TOKEN"; exit 1; }
[ -f /etc/debian_version ] || { echo "only Debian/Ubuntu are supported"; exit 1; }

echo "==> packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q curl gnupg ca-certificates lsb-release python3 logrotate

if [ "$DISTRO_NGINX" = no ] && [ ! -f /etc/apt/sources.list.d/nginx.list ]; then
  # nginx.org stable: newer than most distro builds (ssl_reject_handshake needs >= 1.19.4)
  . /etc/os-release
  curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor --yes -o /usr/share/keyrings/nginx-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/${ID} ${VERSION_CODENAME} nginx" \
    > /etc/apt/sources.list.d/nginx.list
  printf 'Package: *\nPin: origin nginx.org\nPin-Priority: 900\n' > /etc/apt/preferences.d/99nginx
  apt-get update -q
fi
apt-get install -y -q nginx

NGINX_USER="$(awk '/^[[:space:]]*user[[:space:]]/{gsub(";","",$2); print $2; exit}' /etc/nginx/nginx.conf)"
NGINX_USER="${NGINX_USER:-www-data}"

echo "==> files"
install -d -m 755 /etc/pcdn /var/lib/pcdn /usr/share/pcdn/pages /etc/nginx/pcdn/sites
install -d -m 700 /etc/nginx/pcdn/certs
install -d -m 755 -o "$NGINX_USER" /var/cache/pcdn
install -m 755 "$HERE/pcdn-agent.py" /usr/local/bin/pcdn-agent
install -m 644 "$HERE"/pages/*.html /usr/share/pcdn/pages/
install -m 644 "$HERE/nginx/pcdn-base.conf" /etc/nginx/conf.d/00-pcdn.conf
install -m 644 "$HERE/systemd/pcdn-agent.service" /etc/systemd/system/pcdn-agent.service
rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf
if [ "$IPV6" = no ]; then
  sed -i '/listen \[::\]/d' /etc/nginx/conf.d/00-pcdn.conf
fi

# more connections / open files than the stock config
sed -i 's/^\([[:space:]]*worker_connections\).*/\1 16384;/' /etc/nginx/nginx.conf
grep -q '^worker_rlimit_nofile' /etc/nginx/nginx.conf || sed -i '1i worker_rlimit_nofile 200000;' /etc/nginx/nginx.conf
# nginx.org's nginx.conf only includes conf.d/*.conf — that is where our base lives, so nothing else to do.

umask 077
cat > /etc/pcdn/agent.conf <<EOF
CONTROLLER_URL=$CONTROLLER
EDGE_TOKEN=$TOKEN
NGINX_USER=$NGINX_USER
LISTEN_IPV6=$IPV6
CACHE_MAX_SIZE=$CACHE_SIZE
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

echo "==> services"
nginx -t
systemctl enable --now nginx
systemctl reload nginx
/usr/bin/python3 /usr/local/bin/pcdn-agent once </dev/null || true
systemctl daemon-reload
systemctl enable --now pcdn-agent

echo
echo "Edge installed. Check: systemctl status pcdn-agent ; journalctl -u pcdn-agent -f"
echo "Health: curl -H 'Host: health.pcdn' http://127.0.0.1/__pcdn/health"
