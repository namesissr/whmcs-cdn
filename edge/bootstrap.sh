#!/usr/bin/env bash
# Pasargad CDN — one-command remote edge installer (SPEC §11.1)
#
# Downloads the edge bundle from the controller, unpacks it and runs install.sh with the
# same flags. Intended to be piped from the controller:
#
#   curl -fsSL https://<controller>/edge/bootstrap.sh | sudo bash -s -- \
#       --controller https://<controller> --token edge_xxxxx
#
# The token is a credential: a command-line argument shows up in `ps` and the shell history. Prefer
#   curl -fsSL https://<controller>/edge/bootstrap.sh | sudo PCDN_EDGE_TOKEN=edge_xxxxx bash -s -- \
#       --controller https://<controller>                      (environment, not argv)
# or --token-file /root/edge.token (a 0600 file), or no token at all on a terminal (it is asked for
# without echo). bootstrap.sh hands it to install.sh through the environment, never as an argument.
#
# Options (all passed through to install.sh):
#   --controller <url>   controller API base URL (required; https:// only, see --insecure-http)
#   --token edge_xxx     the node's one-time edge token (required unless --upgrade; see above)
#   --token-file <path>  read the token from a file instead
#   --insecure-http      allow a plain http:// controller URL (isolated test networks only: the
#                        bundle, the token and every later config pull then travel unencrypted)
#   --region home|global   edge region / pool
#   --role general|tunnel  edge role (maps to the edge group)
#   --cache-size 50g     max cache disk per site (default 10g)
#   --http-port N        public HTTP port (default 80)
#   --https-port N       public HTTPS port (default 443)
#   --no-ipv6            do not listen on IPv6
#   --no-geoip           do not download the country database
#   --http3              nginx.org mainline nginx with HTTP/3 (QUIC); open UDP/<https-port>
#   --no-http3           back to the distro nginx (default)
#   --cc bbr|cubic       TCP congestion control (default bbr)
#   --upgrade            update an installed edge in place
#   --harden-net         opt-in nftables host guard (SPEC §16.3); --no-harden-net removes it
#   --no-avif            do not install libavif-bin (AVIF image output)
#   --functions          opt-in edge functions (SPEC §16.9, sandboxed QuickJS service pcdn-fn);
#                        --no-functions removes it
#   --no-origin-guard    do not install the nftables origin guard (default on: nginx workers may not
#                        connect to loopback / private / metadata addresses); --origin-guard re-adds it
set -euo pipefail

CONTROLLER=""
TOKEN="${PCDN_EDGE_TOKEN:-}"
TOKEN_FILE=""
INSECURE_HTTP=no
UPGRADE=no
PASS=()   # flags forwarded to install.sh

while [ $# -gt 0 ]; do
  case "$1" in
    --controller) CONTROLLER="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --token-file) TOKEN_FILE="${2:-}"; shift 2 ;;
    --insecure-http) INSECURE_HTTP=yes; PASS+=("$1"); shift ;;
    --upgrade) UPGRADE=yes; PASS+=("$1"); shift ;;
    --region|--role|--cache-size|--http-port|--https-port|--cc)
      PASS+=("$1" "${2:-}"); shift 2 ;;
    --no-ipv6|--no-geoip|--http3|--no-http3|--harden-net|--no-harden-net|--avif|--no-avif)
      PASS+=("$1"); shift ;;
    --functions|--no-functions)   # SPEC §16.9 edge functions (opt-in)
      PASS+=("$1"); shift ;;
    --origin-guard|--no-origin-guard)
      PASS+=("$1"); shift ;;
    *) echo "bootstrap: unknown option: $1" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "bootstrap: run as root (use: sudo bash)" >&2; exit 1; }
if [ -n "$TOKEN_FILE" ]; then
  [ -r "$TOKEN_FILE" ] || { echo "bootstrap: cannot read the token file $TOKEN_FILE" >&2; exit 1; }
  TOKEN="$(tr -d ' \t\r\n' < "$TOKEN_FILE")"
fi
# no token given on a terminal: ask for it (not echoed); an --upgrade keeps the installed token
if [ -z "$TOKEN" ] && [ "$UPGRADE" != yes ] && (: </dev/tty) 2>/dev/null; then
  read -r -s -p "Edge token: " TOKEN </dev/tty || true
  echo >&2
fi
# an --upgrade of an installed edge reuses its controller URL (as install.sh --upgrade does)
if [ -z "$CONTROLLER" ] && [ "$UPGRADE" = yes ] && [ -r /etc/pcdn/agent.conf ]; then
  CONTROLLER="$(sed -n 's/^CONTROLLER_URL=//p' /etc/pcdn/agent.conf | tail -1 | tr -d "\"' \r")"
fi
[ -n "$CONTROLLER" ] && { [ -n "$TOKEN" ] || [ "$UPGRADE" = yes ]; } || {
  echo "usage: bootstrap.sh --controller <url> [--token <edge_token> | --token-file <path>] [flags]" >&2
  echo "       bootstrap.sh --upgrade   (an installed edge: controller URL from /etc/pcdn/agent.conf)" >&2
  echo "       (or the token in PCDN_EDGE_TOKEN; not needed with --upgrade)" >&2; exit 1; }

CONTROLLER="${CONTROLLER%/}"
case "$CONTROLLER" in
  https://?*) ;;
  http://?*)
    if [ "$INSECURE_HTTP" != yes ]; then
      echo "bootstrap: refusing the plain-http controller URL $CONTROLLER: the bundle, the edge token and" >&2
      echo "  every config pull would travel unencrypted. Use https://, or pass --insecure-http on an" >&2
      echo "  isolated test network." >&2
      exit 1
    fi
    echo "warning: --insecure-http: talking to the controller over plain HTTP" >&2 ;;
  *) echo "bootstrap: --controller must be an https:// URL" >&2; exit 1 ;;
esac
# downloads never follow a redirect away from https (unless --insecure-http)
CURL_PROTO=(--proto '=https' --proto-redir '=https')
[ "$INSECURE_HTTP" = yes ] && CURL_PROTO=(--proto '=http,https' --proto-redir '=http,https')

command -v curl >/dev/null 2>&1 || {
  echo "bootstrap: curl is required"; export DEBIAN_FRONTEND=noninteractive
  apt-get update -q && apt-get install -y -q curl ca-certificates; }
command -v tar >/dev/null 2>&1 || { echo "bootstrap: tar is required" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> downloading edge bundle from $CONTROLLER/edge/bundle.tar.gz"
if ! curl -fsSL "${CURL_PROTO[@]}" "$CONTROLLER/edge/bundle.tar.gz" -o "$TMP/bundle.tar.gz"; then
  echo "bootstrap: failed to download the edge bundle from $CONTROLLER" >&2
  echo "  - check that the controller is reachable and EDGE_BUNDLE_DIR is configured there" >&2
  exit 1
fi

echo "==> unpacking"
tar -xzf "$TMP/bundle.tar.gz" -C "$TMP" || { echo "bootstrap: could not unpack the bundle" >&2; exit 1; }
[ -f "$TMP/edge/install.sh" ] || { echo "bootstrap: install.sh not found in the bundle" >&2; exit 1; }

# record the bundle version so the agent can report it (best-effort)
if curl -fsSL "${CURL_PROTO[@]}" "$CONTROLLER/edge/version" -o "$TMP/version.json" 2>/dev/null; then
  VER="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$TMP/version.json")"
  [ -n "$VER" ] && { install -d -m 755 /etc/pcdn; printf '%s\n' "$VER" > /etc/pcdn/bundle.version || true; }
fi

echo "==> running install.sh"
cd "$TMP/edge"
chmod +x install.sh
# the token travels in the environment (readable by root only), never on install.sh's command line
PCDN_EDGE_TOKEN="$TOKEN" ./install.sh --controller "$CONTROLLER" ${PASS[@]+"${PASS[@]}"}
