#!/usr/bin/env bash
# Pasargad CDN — edge node installer (Ubuntu 24.04 LTS)
#
#   sudo ./install.sh --controller https://cdn-api.pasargadmizban.com --token edge_xxxxx
#
# Uses the distribution nginx (1.24) with the distro dynamic modules:
#   libnginx-mod-http-js (njs >= 0.8.1), -geoip2, -image-filter, -brotli-filter
#
# Options:
#   --region home|global   edge region / DNS pool (default global)
#   --role general|tunnel  edge role, maps to the edge group (default general)
#   --no-ipv6          do not listen on IPv6
#   --cache-size 50g   max disk used by the cache of each site (default 10g)
#   --http-port N      public HTTP port (default 80)
#   --https-port N     public HTTPS port (default 443)
#   --no-geoip         do not download the DB-IP country database (country rules never match)
#   --upgrade          update an installed edge in place: controller, token, ports, IPv6, cache
#                      size, region and role are read from /etc/pcdn/agent.conf (flags still override)
#   --distro-nginx     accepted for compatibility (the distro nginx is always used now)
set -euo pipefail

CONTROLLER=""
TOKEN=""
REGION=""
ROLE=""
IPV6=yes
CACHE_SIZE=10g
HTTP_PORT=80
HTTPS_PORT=443
GEOIP=yes
UPGRADE=no
# F6: worker_shutdown_timeout — bounds how many draining worker generations pile up after reloads.
# 1h matches the default tunnel idle_timeout; use 20-30m on <=4GB nodes. Never seconds (a hard cut).
SHUTDOWN_TIMEOUT=1h
HERE="$(cd "$(dirname "$0")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --controller) CONTROLLER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --role) ROLE="$2"; shift 2 ;;
    --no-ipv6) IPV6=no; shift ;;
    --distro-nginx) shift ;;
    --cache-size) CACHE_SIZE="$2"; shift 2 ;;
    --http-port) HTTP_PORT="$2"; shift 2 ;;
    --https-port) HTTPS_PORT="$2"; shift 2 ;;
    --shutdown-timeout) SHUTDOWN_TIMEOUT="$2"; shift 2 ;;
    --no-geoip) GEOIP=no; shift ;;
    --upgrade) UPGRADE=yes; shift ;;
    *) echo "unknown option: $1"; exit 1 ;;
  esac
done
export SHUTDOWN_TIMEOUT

case "${REGION:-}" in ""|home|global) ;; *) echo "--region must be home or global"; exit 1 ;; esac
case "${ROLE:-}" in ""|general|tunnel) ;; *) echo "--role must be general or tunnel"; exit 1 ;; esac

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
if [ "$UPGRADE" = yes ]; then
  [ -f /etc/pcdn/agent.conf ] || { echo "--upgrade: /etc/pcdn/agent.conf not found (not installed yet?)"; exit 1; }
  conf() { sed -n "s/^$1=//p" /etc/pcdn/agent.conf | tail -1; }
  [ -n "$CONTROLLER" ] || CONTROLLER="$(conf CONTROLLER_URL)"
  [ -n "$TOKEN" ] || TOKEN="$(conf EDGE_TOKEN)"
  [ -n "$REGION" ] || REGION="$(conf REGION)"
  [ -n "$ROLE" ] || ROLE="$(conf GROUP)"
  v="$(conf LISTEN_IPV6)"; [ -n "$v" ] && IPV6="$v"
  v="$(conf CACHE_MAX_SIZE)"; [ -n "$v" ] && CACHE_SIZE="$v"
  v="$(conf HTTP_PORT)"; [ -n "$v" ] && HTTP_PORT="$v"
  v="$(conf HTTPS_PORT)"; [ -n "$v" ] && HTTPS_PORT="$v"
fi
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
install -m 644 "$HERE/systemd/pcdn-geoip-retry.service" /etc/systemd/system/pcdn-geoip-retry.service
install -m 644 "$HERE/systemd/pcdn-geoip-retry.timer" /etc/systemd/system/pcdn-geoip-retry.timer
install -m 755 "$HERE/pcdn-geoip-update.sh" /usr/local/sbin/pcdn-geoip-update
# the agent renders /etc/nginx/pcdn/http.conf (base config) + sites; conf.d only includes it
echo 'include /etc/nginx/pcdn/http.conf;' > /etc/nginx/conf.d/00-pcdn.conf
rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf

# >>> nginx.conf edits (idempotent; edge/tests/test_agent.py runs this block against the stock file)
# directives that our http.conf sets would be "duplicate" next to the stock nginx.conf ones
sed -i -E 's/^([[:space:]]*)(gzip[[:space:]]+on;|ssl_protocols[[:space:]]|ssl_prefer_server_ciphers[[:space:]]|keepalive_timeout[[:space:]])/\1# pcdn (set in pcdn http.conf): \2/' /etc/nginx/nginx.conf
# many long-lived connections (tunnel mode): every proxied stream holds 2 descriptors
sed -i 's/^\([[:space:]]*worker_connections\).*/\1 65535;/' /etc/nginx/nginx.conf
# F4: keep multi_accept OFF — forcing it on piles long-lived tunnel connections onto one worker,
# capping the node at one core and one 65535-connection budget. reuseport (in pcdn http.conf)
# spreads new connections across workers instead.
if grep -q '^[[:space:]]*#*[[:space:]]*multi_accept' /etc/nginx/nginx.conf; then
  sed -i 's/^\([[:space:]]*\)#*[[:space:]]*multi_accept.*/\1multi_accept off;/' /etc/nginx/nginx.conf
else
  sed -i 's/^\([[:space:]]*\)\(worker_connections.*\)$/\1\2\n\1multi_accept off;/' /etc/nginx/nginx.conf
fi
if grep -q '^worker_rlimit_nofile' /etc/nginx/nginx.conf; then
  sed -i 's/^worker_rlimit_nofile.*/worker_rlimit_nofile 524288;/' /etc/nginx/nginx.conf
else
  sed -i '1i worker_rlimit_nofile 524288;' /etc/nginx/nginx.conf
fi
# F6: worker_shutdown_timeout so a reload's draining workers are eventually reclaimed instead of
# pinned indefinitely by long-lived tunnels (grows memory until the OOM killer drops tunnels).
_SHUTDOWN_TIMEOUT="${SHUTDOWN_TIMEOUT:-1h}"
if grep -q '^[[:space:]]*worker_shutdown_timeout' /etc/nginx/nginx.conf; then
  sed -i "s/^[[:space:]]*worker_shutdown_timeout.*/worker_shutdown_timeout ${_SHUTDOWN_TIMEOUT};/" /etc/nginx/nginx.conf
else
  sed -i "1a worker_shutdown_timeout ${_SHUTDOWN_TIMEOUT};" /etc/nginx/nginx.conf
fi
# <<< nginx.conf edits
install -d -m 755 /etc/systemd/system/nginx.service.d
# F24: bias the OOM killer away from nginx (the agent is biased toward it) so a memory spike drops
# the accounting agent, not the workers carrying live tunnels.
cat > /etc/systemd/system/nginx.service.d/pcdn-limits.conf <<'EOF'
[Service]
LimitNOFILE=1048576
OOMScoreAdjust=-500
EOF

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
ERROR_LOG=/var/log/nginx/error.log
EOF
# region / role (maps to the edge group): the agent reports these so a fresh node self-registers
# into the right pool (SPEC §11.1). Written only when given; the controller already holds them
# from when the token was minted, and never re-writes them once an operator edits the panel.
[ -n "$REGION" ] && echo "REGION=$REGION" >> /etc/pcdn/agent.conf
[ -n "$ROLE" ] && echo "GROUP=$ROLE" >> /etc/pcdn/agent.conf
# F14/F3: tunnel-role nodes favour throughput over TLS first-byte latency; raise the TLS/relay
# buffers and the per-stream HTTP/2 upload buffer (memory cost ~ concurrent streams × size).
if [ "$ROLE" = tunnel ]; then
  { echo "SSL_BUFFER_SIZE=16k"; echo "TUNNEL_H2_BODY_BUFFER=512k"; } >> /etc/pcdn/agent.conf
fi
# F15: prefer the local systemd-resolved stub, which retries upstream DNS servers itself, so a single
# lost query does not stall a tunnel connect for 5 s and 502. Falls back to the public defaults.
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  echo "RESOLVER=127.0.0.53" >> /etc/pcdn/agent.conf
fi
umask 022

cat > /etc/logrotate.d/pcdn <<'EOF'
/var/log/nginx/pcdn-access.log {
    daily
    rotate 6
    maxsize 1G
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
# F23: run logrotate hourly so `maxsize 1G` is actually enforced (each unit still rotates only when
# its own conditions are met, so this is harmless for other logs).
if [ -f /lib/systemd/system/logrotate.timer ] || [ -f /usr/lib/systemd/system/logrotate.timer ]; then
  install -d -m 755 /etc/systemd/system/logrotate.timer.d
  cat > /etc/systemd/system/logrotate.timer.d/pcdn.conf <<'EOF'
[Timer]
OnCalendar=
OnCalendar=hourly
EOF
fi

# kernel tuning for many long-lived connections (VPN tunnels) and high-latency clients
modprobe tcp_bbr 2>/dev/null || true
echo tcp_bbr > /etc/modules-load.d/pcdn-bbr.conf
# F30: 999- so it sorts after /etc/sysctl.d/99-sysctl.conf at boot; drop the old 99- name on upgrade.
rm -f /etc/sysctl.d/99-pcdn.conf
# >>> pcdn sysctl (edge/tests/test_agent.py parses this heredoc)
cat > /etc/sysctl.d/999-pcdn.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fastopen = 3
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 131072 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
# the cross-border path is lossy; don't cache a bad congestion window onto the next connection,
# and recover faster from tail losses on long-lived tunnel streams
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_sack = 1
# F31: raise the system-wide open-file ceiling without clamping below systemd's high defaults; the
# per-process caps (LimitNOFILE / worker_rlimit_nofile) remain the real limit. fs.nr_open is left at
# the kernel default (must stay >= the per-process cap).
fs.file-max = 9223372036854775807
EOF
# <<< pcdn sysctl
# F19: make conntrack tuning survive netfilter loading after install / after a reboot, and resize the
# hash table. Loading nf_conntrack without a ruleset adds no per-packet tracking on current kernels.
echo nf_conntrack > /etc/modules-load.d/pcdn-conntrack.conf
modprobe nf_conntrack 2>/dev/null || true
echo 'options nf_conntrack hashsize=262144' > /etc/modprobe.d/pcdn-conntrack.conf
[ -w /sys/module/nf_conntrack/parameters/hashsize ] && echo 262144 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
# always write the file so it exists when the module eventually loads (was previously gated on the
# module already being loaded, so the tuning was lost after a reboot)
cat > /etc/sysctl.d/999-pcdn-conntrack.conf <<'EOF'
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
EOF
rm -f /etc/sysctl.d/99-pcdn-conntrack.conf
sysctl --system >/dev/null 2>&1 || true

# F30: verify the values actually took effect (a stray /etc/sysctl.conf entry, or the module not
# being loaded yet, can silently override them) and warn per key rather than failing silently.
for kv in "net.ipv4.tcp_congestion_control=bbr" "net.core.somaxconn=65535" \
          "net.ipv4.ip_local_port_range=10240	65535" "net.ipv4.tcp_keepalive_time=300" \
          "net.core.default_qdisc=fq"; do
  key="${kv%%=*}"; want="${kv#*=}"
  got="$(sysctl -n "$key" 2>/dev/null || true)"
  [ "$got" = "$want" ] || echo "warning: sysctl $key is '$got', expected '$want' (check /etc/sysctl.conf)"
done
# F30: attach fq now on single-queue interfaces only (replacing mq on a multiqueue NIC would reduce
# throughput; a reboot picks up default_qdisc=fq cleanly there).
IF="$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')"
if [ -n "$IF" ]; then
  if [ "$(ls -d "/sys/class/net/$IF/queues/tx-"* 2>/dev/null | wc -l)" -le 1 ]; then
    tc qdisc replace dev "$IF" root fq 2>/dev/null || true
  else
    echo "warning: $IF is multiqueue; reboot to attach fq (default_qdisc) per hardware queue"
  fi
fi

echo "==> GeoIP (DB-IP IP to Country Lite, CC BY 4.0)"
systemctl daemon-reload
if [ "$GEOIP" = yes ]; then
  /usr/local/sbin/pcdn-geoip-update || echo "warning: GeoIP download failed; the daily retry timer will keep trying"
  systemctl enable --now pcdn-geoip.timer
  systemctl enable --now pcdn-geoip-retry.timer   # F9: retry daily while the DB is missing
fi

echo "==> services"
# an empty tree first so nginx can start before the agent's first sync
PCDN_CONFIG=/etc/pcdn/agent.conf /usr/bin/python3 /usr/local/bin/pcdn-agent bootstrap
nginx -t
systemctl enable --now nginx
systemctl reload nginx
PCDN_CONFIG=/etc/pcdn/agent.conf /usr/bin/python3 /usr/local/bin/pcdn-agent once </dev/null || true
# enable for boot, then restart so an --upgrade actually loads the NEW agent code:
# `enable --now` would NOT restart an already-running service, leaving the old code in memory.
systemctl enable pcdn-agent
systemctl restart pcdn-agent

echo
echo "Edge installed. Check: systemctl status pcdn-agent ; journalctl -u pcdn-agent -f"
echo "Health: curl -H 'Host: health.pcdn' http://127.0.0.1:$HTTP_PORT/__pcdn/health"
