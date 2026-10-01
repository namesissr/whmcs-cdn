#!/usr/bin/env bash
# Pasargad CDN — edge node installer (Ubuntu 24.04 LTS)
#
#   sudo ./install.sh --controller https://cdn-api.pasargadmizban.com --token edge_xxxxx
#
# Uses the distribution nginx (1.24) with the distro dynamic modules:
#   libnginx-mod-http-js (njs >= 0.8.1), -geoip2, -image-filter, -brotli-filter
# or, with --http3, nginx.org mainline (HTTP/3 + QUIC) with the nginx.org modules (njs,
# image-filter). nginx.org has no geoip2 / brotli build: the agent detects which module files are
# present and renders their directives only then (country rules fail open, gzip only).
#
# Options:
#   --region home|global   edge region / DNS pool (default global)
#   --role general|tunnel  edge role, maps to the edge group (default general)
#   --no-ipv6          do not listen on IPv6
#   --cache-size 50g   max disk used by the cache of each site (default 10g)
#   --http-port N      public HTTP port (default 80)
#   --https-port N     public HTTPS port (default 443)
#   --no-geoip         do not download the DB-IP country database (country rules never match)
#   --http3            opt-in: nginx.org mainline nginx (HTTP/3 over QUIC). Open UDP/<https-port>.
#   --no-http3         go back to the distro nginx (overrides HTTP3=yes read by --upgrade)
#   --cc bbr|cubic     TCP congestion control (default bbr)
#   --upgrade          update an installed edge in place: controller, token, ports, IPv6, cache
#                      size, region, role, --http3 and --cc are read from /etc/pcdn/agent.conf
#                      (flags still override); LOGSHIP_*, CAPACITY_MBPS, FAIR_SHARE_PCT,
#                      NODE_NAME and SPEED_FILE set there are kept
#   --distro-nginx     same as --no-http3 (the default)
#   --harden-net       opt-in host network guard (SPEC §16.3): nftables table pcdn_guard (SYN rate limits
#                      per /24 and global, SYN proxy for the HTTP(S) ports when the kernel supports it,
#                      invalid-conntrack drop, per-source UDP/<https-port> limit, ICMP echo limit; SSH
#                      ports and the controller are allow-listed first). Values: GUARD_* in agent.conf.
#                      A complement to datacenter scrubbing, never a replacement.
#   --no-harden-net    remove the guard (table, service, sysctls); --upgrade keeps the installed state
#   --no-avif          do not install libavif-bin (AVIF output then needs Pillow's own AVIF plugin);
#                      default: installed when the distribution has it (SPEC §16.6)
#   --functions        opt-in edge functions (SPEC §16.9): package quickjs (universe) + service pcdn-fn, which
#                      runs customer JavaScript in one sandboxed QuickJS process per invocation (Landlock +
#                      seccomp + rlimits + CPU timer inside a DynamicUser / PrivateNetwork systemd unit).
#                      Needs Landlock in the kernel (Ubuntu 24.04: yes). The node reports edge_functions
#                      only while pcdn-fn's sandbox self-test passes.
#   --no-functions     remove pcdn-fn (service, bundle, sockets); --upgrade keeps the installed state
# L4 proxy (SPEC §16.4): the stream module is installed (libnginx-mod-stream / built into nginx.org) and
# nginx.conf includes /etc/nginx/pcdn/l4/*.conf at the main context. Open L4_PORT_RANGE (default
# 20000-29999, TCP and UDP) in the host / provider firewall. Images v2: python3-pil + service
# pcdn-imaged (loopback image transformer, sandboxed).
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
HTTP3=""     # yes | no ("" = not given: no, or the installed value on --upgrade)
TCP_CC=""    # bbr | cubic ("" = not given: bbr, or the installed value on --upgrade)
KEEP_CONF="" # operator-tuned agent.conf lines carried over by --upgrade (log export, SPEC §14.3.2)
# F6: worker_shutdown_timeout — bounds how many draining worker generations pile up after reloads.
# 1h matches the default tunnel idle_timeout; use 20-30m on <=4GB nodes. Never seconds (a hard cut).
SHUTDOWN_TIMEOUT=1h
HARDEN_NET=""  # yes | no ("" = not given: no, or the installed GUARD value on --upgrade)
AVIF=""        # yes | no ("" = not given: yes, or the installed value on --upgrade)
FUNCTIONS=""   # yes | no ("" = not given: no, or the installed value on --upgrade)
HERE="$(cd "$(dirname "$0")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --controller) CONTROLLER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --role) ROLE="$2"; shift 2 ;;
    --no-ipv6) IPV6=no; shift ;;
    --distro-nginx|--no-http3) HTTP3=no; shift ;;
    --http3) HTTP3=yes; shift ;;
    --cc) TCP_CC="${2:-}"; shift 2 ;;
    --cache-size) CACHE_SIZE="$2"; shift 2 ;;
    --http-port) HTTP_PORT="$2"; shift 2 ;;
    --https-port) HTTPS_PORT="$2"; shift 2 ;;
    --shutdown-timeout) SHUTDOWN_TIMEOUT="$2"; shift 2 ;;
    --no-geoip) GEOIP=no; shift ;;
    --upgrade) UPGRADE=yes; shift ;;
    --harden-net) HARDEN_NET=yes; shift ;;
    --no-harden-net) HARDEN_NET=no; shift ;;
    --avif) AVIF=yes; shift ;;
    --no-avif) AVIF=no; shift ;;
    --functions) FUNCTIONS=yes; shift ;;
    --no-functions) FUNCTIONS=no; shift ;;
    *) echo "unknown option: $1"; exit 1 ;;
  esac
done
export SHUTDOWN_TIMEOUT

case "${REGION:-}" in ""|home|global) ;; *) echo "--region must be home or global"; exit 1 ;; esac
case "${ROLE:-}" in ""|general|tunnel) ;; *) echo "--role must be general or tunnel"; exit 1 ;; esac
case "${TCP_CC:-}" in ""|bbr|cubic) ;; *) echo "--cc must be bbr or cubic"; exit 1 ;; esac

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
  if [ -z "$TCP_CC" ]; then v="$(conf TCP_CC)"; case "$v" in bbr|cubic) TCP_CC="$v" ;; esac; fi
  if [ -z "$HTTP3" ]; then v="$(conf HTTP3)"; case "$v" in yes|no) HTTP3="$v" ;; esac; fi
  # wave 8: the host guard (SPEC §16.3) and AVIF tooling (§16.6) stay as installed unless a flag says
  if [ -z "${HARDEN_NET:-}" ]; then v="$(conf GUARD)"; case "$v" in yes|no) HARDEN_NET="$v" ;; esac; fi
  if [ -z "${AVIF:-}" ]; then v="$(conf AVIF)"; case "$v" in yes|no) AVIF="$v" ;; esac; fi
  # SPEC §16.9 edge functions stay as installed unless --functions / --no-functions says otherwise
  if [ -z "${FUNCTIONS:-}" ]; then v="$(conf FUNCTIONS)"; case "$v" in yes|no) FUNCTIONS="$v" ;; esac; fi
  # kept across --upgrade: log-export tunables (SPEC §14.3.2) and the wave-7 node settings an operator
  # may have added (SPEC §15.2 fair-share capacity / share, §15.6 speed-test node name / file)
  # and the wave-8 settings (SPEC §16.3 GUARD_* values, §16.4 L4_*, §16.6 IMAGE*/IMAGED)
  KEEP_CONF="$(grep -E '^(LOGSHIP_(SPOOL_DIR|SPOOL_MAX_MB|INTERVAL|TIMEOUT)|CAPACITY_MBPS|FAIR_SHARE_PCT|NODE_NAME|SPEED_FILE|L4_PORT_RANGE|L4_ACCESS_LOG|IMAGED|IMAGE_(PORT|WORKERS|MAX_SOURCE_MB)|GUARD_(SSH_PORTS|ALLOW|SYN_RATE|SYN_BURST|SYN_GLOBAL|UDP_RATE|ICMP_RATE|SYNPROXY)|FN_(WALL_MS|WORKERS|SITE_WORKERS|MAX_FETCHES|FETCH_TIMEOUT_MS|STARTUP_MS|QUEUE_MS))=' \
    /etc/pcdn/agent.conf || true)"
fi
TCP_CC="${TCP_CC:-bbr}"
HTTP3="${HTTP3:-no}"
HARDEN_NET="${HARDEN_NET:-no}"
AVIF="${AVIF:-yes}"
FUNCTIONS="${FUNCTIONS:-no}"
[ -n "$CONTROLLER" ] && [ -n "$TOKEN" ] || { echo "usage: $0 --controller URL --token TOKEN"; exit 1; }
[ -f /etc/debian_version ] || { echo "only Ubuntu 24.04 (or a Debian derivative with njs >= 0.8.1) is supported"; exit 1; }
case "$HTTP_PORT$HTTPS_PORT" in *[!0-9]*) echo "ports must be numeric"; exit 1 ;; esac
. /etc/os-release
if [ "${ID:-}" != ubuntu ] || [ "${VERSION_ID%%.*}" -lt 24 ]; then
  echo "warning: tested on Ubuntu 24.04; continuing on ${PRETTY_NAME:-unknown}"
fi

echo "==> packages"
export DEBIAN_FRONTEND=noninteractive
# the published nginx.org signing key (https://nginx.org/en/linux_packages.html)
NGINX_KEY_FPR=573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62
NGINX_KEYRING=/usr/share/keyrings/nginx-archive-keyring.gpg
MODULES_DIR=/usr/lib/nginx/modules

# (pipelines below end in `grep ... >/dev/null`, not `grep -q`: with pipefail an early grep exit
# could SIGPIPE the writer and turn a match into a failure)
installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep "ok installed" >/dev/null; }
# dpkg conffile policy for the nginx packages only: keep our edited nginx.conf on a plain upgrade;
# after a flavour swap take the new package's stock file (it was moved aside).
NGINX_APT_OPTS="-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
# the distro and nginx.org nginx packages conflict: remove the other flavour first. Its
# /etc/nginx/nginx.conf is moved aside (*.pcdn-bak) so the new package installs its own stock file
# (our edits below are re-applied to it), and pcdn's include is parked so the new package's
# postinst can start nginx before the module load_module lines exist.
swap_out() {
  local pkgs="$*"
  [ -n "$pkgs" ] || return 0
  echo "    replacing: $pkgs"
  if [ -f /etc/nginx/nginx.conf ]; then mv -f /etc/nginx/nginx.conf /etc/nginx/nginx.conf.pcdn-bak; fi
  if [ -f /etc/nginx/conf.d/00-pcdn.conf ]; then
    mv -f /etc/nginx/conf.d/00-pcdn.conf /etc/nginx/00-pcdn.conf.parked
  fi
  # shellcheck disable=SC2086
  apt-get remove -y -q $pkgs
  NGINX_APT_OPTS="-o Dpkg::Options::=--force-confnew -o Dpkg::Options::=--force-confmiss"
}

if [ "$HTTP3" = yes ]; then
  # SPEC §14.1: nginx.org mainline (built --with-http_v3_module) + the nginx.org dynamic modules
  apt-get update -q
  apt-get install -y -q curl ca-certificates gnupg python3 logrotate gzip
  CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
  case "${ID:-}" in ubuntu|debian) NGINX_DISTRO="$ID" ;; *) NGINX_DISTRO=ubuntu ;; esac
  [ -n "$CODENAME" ] || { echo "--http3: cannot determine the distribution codename"; exit 1; }
  curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor > "$NGINX_KEYRING.tmp"
  if ! gpg --dry-run --quiet --no-keyring --import --import-options import-show "$NGINX_KEYRING.tmp" 2>/dev/null \
      | tr -d ' ' | grep -i "$NGINX_KEY_FPR" >/dev/null; then
    rm -f "$NGINX_KEYRING.tmp"
    echo "--http3: the downloaded nginx.org key is not $NGINX_KEY_FPR; refusing to add the repository"; exit 1
  fi
  mv -f "$NGINX_KEYRING.tmp" "$NGINX_KEYRING"
  chmod 644 "$NGINX_KEYRING"
  echo "deb [signed-by=$NGINX_KEYRING] https://nginx.org/packages/mainline/$NGINX_DISTRO $CODENAME nginx" \
    > /etc/apt/sources.list.d/nginx.list
  printf 'Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n' > /etc/apt/preferences.d/99nginx
  apt-get update -q
  if installed nginx-common; then
    swap_out $(dpkg-query -W -f='${Package} ${Status}\n' 'libnginx-mod-*' nginx nginx-core nginx-full nginx-light \
                 nginx-extras nginx-common 2>/dev/null | awk '/ok installed/{print $1}')
  fi
  # shellcheck disable=SC2086
  apt-get install -y -q $NGINX_APT_OPTS nginx nginx-module-njs nginx-module-image-filter
  # modules nginx.org may or may not publish for this build: used when present, skipped otherwise
  for pkg in nginx-module-geoip2 nginx-module-brotli; do
    # shellcheck disable=SC2086
    if apt-cache show "$pkg" >/dev/null 2>&1; then apt-get install -y -q $NGINX_APT_OPTS "$pkg" || true; fi
  done
  NJS_PKG=nginx-module-njs
  nginx -V 2>&1 | grep -- '--with-http_v3_module' >/dev/null || echo "warning: this nginx build has no HTTP/3 support"
else
  if installed nginx && dpkg-query -W -f='${Maintainer}' nginx 2>/dev/null | grep -i 'nginx packaging' >/dev/null; then
    # back from --http3: the distro build carries every module we need
    swap_out $(dpkg-query -W -f='${Package} ${Status}\n' nginx 'nginx-module-*' 2>/dev/null \
                 | awk '/ok installed/{print $1}')
  fi
  # an old install may have pinned nginx.org packages; the distro build carries the modules we need
  rm -f /etc/apt/sources.list.d/nginx.list /etc/apt/preferences.d/99nginx
  apt-get update -q
  apt-get install -y -q curl ca-certificates python3 logrotate gzip
  # shellcheck disable=SC2086
  apt-get install -y -q $NGINX_APT_OPTS \
    nginx libnginx-mod-http-js libnginx-mod-http-geoip2 libnginx-mod-http-image-filter libnginx-mod-http-brotli-filter \
    libnginx-mod-stream
  NJS_PKG=libnginx-mod-http-js
fi
# SPEC §16.6 images v2 (best effort: without them the node reports image_transform / avif false and
# keeps serving image_filter resizes / originals)
apt-get install -y -q python3-pil || echo "warning: python3-pil not installed: no image transformer (images v2)"
if [ "$AVIF" = yes ]; then
  if apt-cache show libavif-bin >/dev/null 2>&1; then
    apt-get install -y -q libavif-bin || echo "warning: libavif-bin not installed: no AVIF output"
  else
    echo "warning: libavif-bin is not available here (enable 'universe'?): no AVIF output unless Pillow has AVIF"
  fi
fi
if [ -f /etc/nginx/00-pcdn.conf.parked ]; then mv -f /etc/nginx/00-pcdn.conf.parked /etc/nginx/conf.d/00-pcdn.conf; fi

# js_periodic / js_shared_dict_zone need njs >= 0.8.1 (nginx.org versions read "<nginx>+<njs>-<rel>")
NJS_VER="$(dpkg-query -W -f='${Version}' "$NJS_PKG" 2>/dev/null | sed 's/^[0-9]*://; s/-.*//; s/^.*+//')"
if ! printf '0.8.1\n%s\n' "$NJS_VER" | sort -V -C; then
  echo "njs $NJS_VER is too old (need >= 0.8.1)"; exit 1
fi

NGINX_USER="$(awk '/^[[:space:]]*user[[:space:]]/{gsub(";","",$2); print $2; exit}' /etc/nginx/nginx.conf)"
NGINX_USER="${NGINX_USER:-www-data}"

echo "==> files"
install -d -m 755 /etc/pcdn /var/lib/pcdn /usr/share/pcdn/pages /usr/share/pcdn/njs /usr/share/pcdn/nginx /usr/share/pcdn/geo
install -d -m 755 -o "$NGINX_USER" /var/cache/pcdn
# the nginx.org build runs its workers as "nginx", the distro one as "www-data": the cache follows
chown -R "$NGINX_USER" /var/cache/pcdn 2>/dev/null || true
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
install -m 644 "$HERE/systemd/pcdn-imaged.service" /etc/systemd/system/pcdn-imaged.service
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
# SPEC §16.4: the agent's L4 proxy (stream {}) lives in /etc/nginx/pcdn/l4/*.conf, main context (the
# glob matches nothing until a site has an L4 app; the agent renders it only when this line exists)
if ! grep -q '^include /etc/nginx/pcdn/l4/\*\.conf;' /etc/nginx/nginx.conf; then
  printf '\n# pcdn L4 proxy (SPEC §16.4): stream {} rendered by pcdn-agent\ninclude /etc/nginx/pcdn/l4/*.conf;\n' \
    >> /etc/nginx/nginx.conf
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
# >>> pcdn load_module (nginx.org packages have no modules-enabled/; edge/tests/test_agent.py runs this)
# one load_module line per optional module file present (the agent renders a module's directives
# only when its file exists, so every present module must be loaded)
if [ "$HTTP3" = yes ]; then
  for so in ngx_http_js_module.so ngx_http_image_filter_module.so ngx_http_geoip2_module.so \
            ngx_http_brotli_filter_module.so; do
    if [ -f "$MODULES_DIR/$so" ] && ! grep -q "^[[:space:]]*load_module[[:space:]].*/$so;" /etc/nginx/nginx.conf; then
      sed -i "1i load_module $MODULES_DIR/$so;" /etc/nginx/nginx.conf
    fi
  done
  [ -f "$MODULES_DIR/ngx_http_geoip2_module.so" ] || echo "warning: no geoip2 module for this nginx build:" \
    "country firewall rules never match and tunnel allowed_countries fails open"
  [ -f "$MODULES_DIR/ngx_http_brotli_filter_module.so" ] || echo "warning: no brotli module for this nginx" \
    "build: responses are compressed with gzip only"
fi
# <<< pcdn load_module
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
TCP_CC=$TCP_CC
HTTP3=$HTTP3
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
# >>> pcdn keep logship (edge/tests/test_analytics_logship.py runs this)
# SPEC §14.3.2 log export: the agent defaults are a spool next to its state file
# (/var/lib/pcdn/logship), capped at LOGSHIP_SPOOL_MAX_MB=256, shipped every LOGSHIP_INTERVAL=30 s with
# LOGSHIP_TIMEOUT=30 s per POST; values an operator added to agent.conf survive --upgrade
if [ -n "$KEEP_CONF" ]; then printf '%s\n' "$KEEP_CONF" >> /etc/pcdn/agent.conf; fi
# <<< pcdn keep logship
# >>> pcdn wave8 conf (edge/tests/test_agent.py runs this)
# SPEC §16.3 / §16.6 install choices (read back by --upgrade) and the SSH ports the guard never limits
# (detected from sshd unless the operator set GUARD_SSH_PORTS)
printf 'GUARD=%s\nAVIF=%s\nFUNCTIONS=%s\n' "$HARDEN_NET" "$AVIF" "${FUNCTIONS:-no}" >> /etc/pcdn/agent.conf
if ! grep -q '^GUARD_SSH_PORTS=' /etc/pcdn/agent.conf; then
  SSH_PORTS="$( (sshd -T 2>/dev/null || true) | awk '$1 == "port" {print $2}' | sort -un | tr '\n' ' ' | sed 's/ *$//')"
  echo "GUARD_SSH_PORTS=${SSH_PORTS:-22}" >> /etc/pcdn/agent.conf
fi
# <<< pcdn wave8 conf
umask 022

cat > /etc/logrotate.d/pcdn <<'EOF'
/var/log/nginx/pcdn-access.log /var/log/nginx/pcdn-l4.log {
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
# --cc (SPEC §14.1): bbr (default) or cubic
if [ "$TCP_CC" = bbr ]; then
  modprobe tcp_bbr 2>/dev/null || true
  echo tcp_bbr > /etc/modules-load.d/pcdn-bbr.conf
else
  rm -f /etc/modules-load.d/pcdn-bbr.conf
fi
# F30: 999- so it sorts after /etc/sysctl.d/99-sysctl.conf at boot; drop the old 99- name on upgrade.
rm -f /etc/sysctl.d/99-pcdn.conf
# default_qdisc fq is required by bbr and stays the default (SPEC §15.2): per-flow fair queueing on
# the NIC is what keeps one busy tunnel from starving the others at the packet level; nginx 1.24
# cannot rate-limit tunnel streams itself (see docs/EDGE.md, fair share).
# >>> pcdn sysctl (edge/tests/test_agent.py runs this heredoc; it expands only ${TCP_CC})
cat > /etc/sysctl.d/999-pcdn.conf <<EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = ${TCP_CC}
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
for kv in "net.ipv4.tcp_congestion_control=$TCP_CC" "net.core.somaxconn=65535" \
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

# >>> pcdn guard (SPEC §16.3; opt-in, removable)
GUARD_UNIT=/etc/systemd/system/pcdn-guard.service
if [ "$HARDEN_NET" = yes ]; then
  echo "==> host network guard (nftables table pcdn_guard)"
  command -v nft >/dev/null 2>&1 || apt-get install -y -q nftables
  install -m 644 "$HERE/systemd/pcdn-guard.service" "$GUARD_UNIT"
  guard() { PCDN_CONFIG=/etc/pcdn/agent.conf /usr/bin/python3 /usr/local/bin/pcdn-agent guard "$@"; }
  SYNPROXY=""
  # SYN proxy for the HTTP(S) ports only when the kernel accepts the ruleset (GUARD_SYNPROXY=no: never)
  if [ "$(sed -n 's/^GUARD_SYNPROXY=//p' /etc/pcdn/agent.conf | tail -1)" != no ] \
     && guard --synproxy > /etc/pcdn/guard.nft.new && nft -c -f /etc/pcdn/guard.nft.new >/dev/null 2>&1; then
    SYNPROXY=--synproxy
  fi
  guard $SYNPROXY > /etc/pcdn/guard.nft.new
  if nft -c -f /etc/pcdn/guard.nft.new; then
    mv -f /etc/pcdn/guard.nft.new /etc/pcdn/guard.nft
    chmod 644 /etc/pcdn/guard.nft
    if [ -n "$SYNPROXY" ]; then
      # the SYN proxy needs syncookies + timestamps and strict TCP tracking (the third ACK of a proxied
      # handshake must be INVALID so synproxy completes it). Untracked mid-stream connections from
      # before the guard are dropped once.
      printf 'net.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_timestamps = 1\nnet.netfilter.nf_conntrack_tcp_loose = 0\n' \
        > /etc/sysctl.d/999-pcdn-guard.conf
      sysctl -p /etc/sysctl.d/999-pcdn-guard.conf >/dev/null 2>&1 || true
    else
      rm -f /etc/sysctl.d/999-pcdn-guard.conf
      sysctl -w net.netfilter.nf_conntrack_tcp_loose=1 >/dev/null 2>&1 || true
    fi
    systemctl daemon-reload
    systemctl enable pcdn-guard >/dev/null
    systemctl restart pcdn-guard
    echo "    guard active${SYNPROXY:+ (with SYN proxy)}; remove with --no-harden-net"
  else
    rm -f /etc/pcdn/guard.nft.new
    sed -i 's/^GUARD=yes$/GUARD=no/' /etc/pcdn/agent.conf
    echo "warning: nft rejected the guard ruleset; the guard is NOT installed"
  fi
elif [ -f "$GUARD_UNIT" ] || [ -f /etc/pcdn/guard.nft ]; then
  echo "==> removing the host network guard"
  systemctl disable --now pcdn-guard >/dev/null 2>&1 || true
  nft delete table inet pcdn_guard 2>/dev/null || true
  rm -f "$GUARD_UNIT" /etc/pcdn/guard.nft /etc/pcdn/guard.nft.new /etc/sysctl.d/999-pcdn-guard.conf
  sysctl -w net.netfilter.nf_conntrack_tcp_loose=1 >/dev/null 2>&1 || true
  systemctl daemon-reload
fi
# <<< pcdn guard

# >>> pcdn functions (SPEC §16.9; opt-in, removable)
FN_UNIT=/etc/systemd/system/pcdn-fn.service
NGINX_GROUP="$(id -gn "$NGINX_USER" 2>/dev/null || echo www-data)"
if [ "$FUNCTIONS" = yes ]; then
  echo "==> edge functions (pcdn-fn: sandboxed QuickJS workers)"
  command -v qjs >/dev/null 2>&1 || apt-get install -y -q quickjs \
    || echo "warning: package quickjs is not available (enable the 'universe' component)"
  if command -v qjs >/dev/null 2>&1; then
    install -d -m 755 /usr/share/pcdn/fn
    install -m 644 "$HERE/fn/runtime.js" /usr/share/pcdn/fn/runtime.js
    install -m 755 "$HERE/pcdn-fn.py" /usr/local/bin/pcdn-fn
    install -m 644 "$HERE/systemd/pcdn-fn.service" "$FN_UNIT"
    # nginx workers connect to pcdn-fn's socket and pcdn-fn to nginx's fetch() socket through this group
    install -d -m 755 /etc/systemd/system/pcdn-fn.service.d
    printf '[Service]\nSupplementaryGroups=\nSupplementaryGroups=%s\n' "$NGINX_GROUP" \
      > /etc/systemd/system/pcdn-fn.service.d/group.conf
    # the fetch() socket directory must exist before nginx loads a config that listens on it (also at boot)
    printf 'd /run/pcdn-fnfetch 0750 root %s -\n' "$NGINX_GROUP" > /etc/tmpfiles.d/pcdn-fn.conf
    systemd-tmpfiles --create /etc/tmpfiles.d/pcdn-fn.conf
    # the code bundle written by the agent (root:<nginx group> 0750 / 0640; pcdn-fn reads it via the group)
    install -d -m 750 -o root -g "$NGINX_GROUP" /var/lib/pcdn-fn
    aval() { v="$(sed -n "s/^$1=//p" /etc/pcdn/agent.conf | tail -1)"; echo "${v:-$2}"; }
    printf 'FN_SOCKET_GROUP=%s\nFN_WALL_MS=%s\nFN_WORKERS=%s\nFN_SITE_WORKERS=%s\nFN_MAX_FETCHES=%s\nFN_FETCH_TIMEOUT_MS=%s\nFN_STARTUP_MS=%s\nFN_QUEUE_MS=%s\n' \
      "$NGINX_GROUP" "$(aval FN_WALL_MS 5000)" "$(aval FN_WORKERS 0)" "$(aval FN_SITE_WORKERS 4)" \
      "$(aval FN_MAX_FETCHES 8)" "$(aval FN_FETCH_TIMEOUT_MS 5000)" "$(aval FN_STARTUP_MS 30)" \
      "$(aval FN_QUEUE_MS 1000)" > /etc/pcdn/fn.conf
    chmod 644 /etc/pcdn/fn.conf
    systemctl daemon-reload
    systemctl enable pcdn-fn >/dev/null
    systemctl restart pcdn-fn
    # the sandbox self-test runs at start; the capability stays false until it passes
    ok=no
    for _ in $(seq 1 20); do
      if grep -q '"ok": true' /run/pcdn-fn/status.json 2>/dev/null; then ok=yes; break; fi
      sleep 1
    done
    if [ "$ok" = yes ]; then
      echo "    pcdn-fn self-test passed ($(sed -n 's/.*"engine": "\([^"]*\)".*/\1/p' /run/pcdn-fn/status.json))"
    else
      echo "warning: pcdn-fn self-test did not pass (see journalctl -u pcdn-fn and /run/pcdn-fn/status.json);"
      echo "         the node does NOT report edge_functions and bound routes follow their on_error setting"
    fi
  else
    sed -i 's/^FUNCTIONS=yes$/FUNCTIONS=no/' /etc/pcdn/agent.conf
    echo "warning: edge functions are NOT installed (no QuickJS engine)"
  fi
elif [ -f "$FN_UNIT" ] || [ -f /usr/local/bin/pcdn-fn ]; then
  echo "==> removing edge functions (pcdn-fn)"
  systemctl disable --now pcdn-fn >/dev/null 2>&1 || true
  # /run/pcdn-fnfetch stays (empty) until reboot: the nginx tree on disk may still listen there until
  # the agent re-renders without functions (its render revision includes FUNCTIONS), and nginx -t below
  # must keep passing
  rm -rf "$FN_UNIT" /etc/systemd/system/pcdn-fn.service.d /etc/tmpfiles.d/pcdn-fn.conf /usr/local/bin/pcdn-fn \
    /usr/share/pcdn/fn /var/lib/pcdn-fn /var/lib/pcdn-fn.new /var/lib/pcdn-fn.old /etc/pcdn/fn.conf
  systemctl daemon-reload
fi
# <<< pcdn functions

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
# >>> pcdn imaged (SPEC §16.6): the loopback image transformer, sandboxed (DynamicUser); its settings
# live in a world-readable file because it cannot read the root-only agent.conf
aval() { v="$(sed -n "s/^$1=//p" /etc/pcdn/agent.conf | tail -1)"; echo "${v:-$2}"; }
umask 022
printf 'IMAGE_PORT=%s\nRESIZE_PORT=%s\nIMAGE_WORKERS=%s\nIMAGE_MAX_SOURCE_MB=%s\n' \
  "$(aval IMAGE_PORT 8090)" "$(aval RESIZE_PORT 8089)" "$(aval IMAGE_WORKERS 2)" "$(aval IMAGE_MAX_SOURCE_MB 20)" \
  > /etc/pcdn/imaged.conf
chmod 644 /etc/pcdn/imaged.conf
if [ "$(aval IMAGED auto)" != no ] && /usr/bin/python3 -c 'import PIL' 2>/dev/null; then
  systemctl enable pcdn-imaged >/dev/null
  systemctl restart pcdn-imaged
else
  systemctl disable --now pcdn-imaged >/dev/null 2>&1 || true
fi
# <<< pcdn imaged

echo
echo "Edge installed. Check: systemctl status pcdn-agent ; journalctl -u pcdn-agent -f"
echo "Health: curl -H 'Host: health.pcdn' http://127.0.0.1:$HTTP_PORT/__pcdn/health"
if [ "$HTTP3" = yes ]; then
  echo
  echo "HTTP/3: allow UDP/$HTTPS_PORT (QUIC) in the host firewall and any provider security group,"
  echo "        e.g. 'ufw allow $HTTPS_PORT/udp' — TCP/$HTTPS_PORT alone keeps clients on HTTP/2."
fi
L4R="$(sed -n 's/^L4_PORT_RANGE=//p' /etc/pcdn/agent.conf | tail -1)"
L4R="${L4R:-20000-29999}"
echo
echo "L4 proxy: allow TCP and UDP $L4R in the host firewall / provider security group (only ports of"
echo "          configured apps listen), e.g. 'ufw allow ${L4R/-/:}/tcp' and 'ufw allow ${L4R/-/:}/udp'."
