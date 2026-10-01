#!/usr/bin/env bash
# Pasargad CDN — one-command remote edge installer (SPEC §11.1)
#
# Downloads the edge bundle from the controller, unpacks it and runs install.sh with the
# same flags. Intended to be piped from the controller:
#
#   curl -fsSL https://<controller>/edge/bootstrap.sh | sudo bash -s -- \
#       --controller https://<controller> --token edge_xxxxx
#
# Options (all passed through to install.sh):
#   --controller <url>   controller API base URL (required)
#   --token edge_xxx     the node's one-time edge token (required)
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
set -euo pipefail

CONTROLLER=""
TOKEN=""
PASS=()   # flags forwarded to install.sh

while [ $# -gt 0 ]; do
  case "$1" in
    --controller) CONTROLLER="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --region|--role|--cache-size|--http-port|--https-port|--cc)
      PASS+=("$1" "${2:-}"); shift 2 ;;
    --no-ipv6|--no-geoip|--upgrade|--http3|--no-http3|--harden-net|--no-harden-net|--avif|--no-avif)
      PASS+=("$1"); shift ;;
    *) echo "bootstrap: unknown option: $1" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "bootstrap: run as root (use: sudo bash)" >&2; exit 1; }
[ -n "$CONTROLLER" ] && [ -n "$TOKEN" ] || {
  echo "usage: bootstrap.sh --controller <url> --token <edge_token> [flags]" >&2; exit 1; }

CONTROLLER="${CONTROLLER%/}"

command -v curl >/dev/null 2>&1 || {
  echo "bootstrap: curl is required"; export DEBIAN_FRONTEND=noninteractive
  apt-get update -q && apt-get install -y -q curl ca-certificates; }
command -v tar >/dev/null 2>&1 || { echo "bootstrap: tar is required" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> downloading edge bundle from $CONTROLLER/edge/bundle.tar.gz"
if ! curl -fsSL "$CONTROLLER/edge/bundle.tar.gz" -o "$TMP/bundle.tar.gz"; then
  echo "bootstrap: failed to download the edge bundle from $CONTROLLER" >&2
  echo "  - check that the controller is reachable and EDGE_BUNDLE_DIR is configured there" >&2
  exit 1
fi

echo "==> unpacking"
tar -xzf "$TMP/bundle.tar.gz" -C "$TMP" || { echo "bootstrap: could not unpack the bundle" >&2; exit 1; }
[ -f "$TMP/edge/install.sh" ] || { echo "bootstrap: install.sh not found in the bundle" >&2; exit 1; }

# record the bundle version so the agent can report it (best-effort)
if curl -fsSL "$CONTROLLER/edge/version" -o "$TMP/version.json" 2>/dev/null; then
  VER="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$TMP/version.json")"
  [ -n "$VER" ] && { install -d -m 755 /etc/pcdn; printf '%s\n' "$VER" > /etc/pcdn/bundle.version || true; }
fi

echo "==> running install.sh"
cd "$TMP/edge"
chmod +x install.sh
./install.sh --controller "$CONTROLLER" --token "$TOKEN" "${PASS[@]}"
