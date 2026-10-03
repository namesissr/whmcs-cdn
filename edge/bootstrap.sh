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
# A freshly provisioned VM (SPEC §23.9) gets a one-time JOIN token instead: PCDN_JOIN_TOKEN=jt_... in the
# environment (or --join-token-file); install.sh exchanges it for the edge token (POST /edge/v1/join).
#
# Pinned releases (SPEC §23.1): --version vX.Y.Z installs exactly that release: bundle.tar.gz?version=...
# plus its .sha256 from the controller, verified with sha256sum -c (a mismatch aborts, nothing installed).
# Without --version, a release the controller pins for this node's group (GET /edge/releases, the group
# follows --role) is installed the same way; a controller without pinned releases -> the live bundle.
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
#   --version vX.Y.Z     install this pinned release (also --version=vX.Y.Z; see above)
#   --join-token-file <path>  one-time join token from a file (SPEC §23.9; or PCDN_JOIN_TOKEN)
#   --upgrade            update an installed edge in place (controller URL from /etc/pcdn/agent.conf)
#   --drain[=minutes]    with --upgrade only (SPEC §22.1): drain the node first (1..120, default 15), upgrade
#                        once drained; the new agent undrains itself (install.sh calls the controller)
#   --shutdown-timeout auto|<time>  nginx worker_shutdown_timeout (SPEC §22.2, default auto by RAM)
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
DRAIN=""
VERSION=""   # --version vX.Y.Z (SPEC §23.1)
ROLE=""
JOIN_TOKEN="${PCDN_JOIN_TOKEN:-}"
JOIN_TOKEN_FILE=""
PASS=()   # flags forwarded to install.sh

while [ $# -gt 0 ]; do
  case "$1" in
    --controller) CONTROLLER="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --token-file) TOKEN_FILE="${2:-}"; shift 2 ;;
    --join-token-file) JOIN_TOKEN_FILE="${2:-}"; shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --version=*) VERSION="${1#--version=}"; shift ;;
    --insecure-http) INSECURE_HTTP=yes; PASS+=("$1"); shift ;;
    --upgrade) UPGRADE=yes; PASS+=("$1"); shift ;;
    --region|--role|--cache-size|--http-port|--https-port|--shutdown-timeout|--cc)
      [ "$1" = --role ] && ROLE="${2:-}"
      PASS+=("$1" "${2:-}"); shift 2 ;;
    --drain) DRAIN=15; shift ;;            # SPEC §22.1 upgrade drain (validated below, forwarded)
    --drain=*) DRAIN="${1#--drain=}"; shift ;;
    --no-ipv6|--no-geoip|--http3|--no-http3|--harden-net|--no-harden-net|--avif|--no-avif)
      PASS+=("$1"); shift ;;
    --functions|--no-functions)   # SPEC §16.9 edge functions (opt-in)
      PASS+=("$1"); shift ;;
    --origin-guard|--no-origin-guard)
      PASS+=("$1"); shift ;;
    *) echo "bootstrap: unknown option: $1" >&2; exit 1 ;;
  esac
done
# >>> pcdn bootstrap drain check (edge/tests/test_install_agent.py runs this block)
if [ -n "$DRAIN" ]; then
  [ "$UPGRADE" = yes ] || { echo "bootstrap: --drain is only valid together with --upgrade" >&2; exit 1; }
  case "$DRAIN" in ''|*[!0-9]*) echo "bootstrap: --drain=<minutes> must be 1..120" >&2; exit 1 ;; esac
  if [ "$((10#$DRAIN))" -lt 1 ] || [ "$((10#$DRAIN))" -gt 120 ]; then
    echo "bootstrap: --drain=<minutes> must be 1..120" >&2; exit 1
  fi
  PASS+=("--drain=$((10#$DRAIN))")
fi
# <<< pcdn bootstrap drain check
# >>> pcdn bootstrap version check (edge/tests/test_wave14.py runs this block)
if [ -n "$VERSION" ] && ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "bootstrap: --version must look like vX.Y.Z (e.g. v2.1.0)" >&2; exit 1
fi
# <<< pcdn bootstrap version check

[ "$(id -u)" -eq 0 ] || { echo "bootstrap: run as root (use: sudo bash)" >&2; exit 1; }
if [ -n "$TOKEN_FILE" ]; then
  [ -r "$TOKEN_FILE" ] || { echo "bootstrap: cannot read the token file $TOKEN_FILE" >&2; exit 1; }
  TOKEN="$(tr -d ' \t\r\n' < "$TOKEN_FILE")"
fi
if [ -n "$JOIN_TOKEN_FILE" ]; then
  [ -r "$JOIN_TOKEN_FILE" ] || { echo "bootstrap: cannot read the join token file $JOIN_TOKEN_FILE" >&2; exit 1; }
  JOIN_TOKEN="$(tr -d ' \t\r\n' < "$JOIN_TOKEN_FILE")"
fi
# no token given on a terminal: ask for it (not echoed); an --upgrade keeps the installed token
if [ -z "$TOKEN" ] && [ -z "$JOIN_TOKEN" ] && [ "$UPGRADE" != yes ] && (: </dev/tty) 2>/dev/null; then
  read -r -s -p "Edge token: " TOKEN </dev/tty || true
  echo >&2
fi
# an --upgrade of an installed edge reuses its controller URL (as install.sh --upgrade does)
if [ -z "$CONTROLLER" ] && [ "$UPGRADE" = yes ] && [ -r /etc/pcdn/agent.conf ]; then
  CONTROLLER="$(sed -n 's/^CONTROLLER_URL=//p' /etc/pcdn/agent.conf | tail -1 | tr -d "\"' \r")"
fi
[ -n "$CONTROLLER" ] && { [ -n "$TOKEN" ] || [ -n "$JOIN_TOKEN" ] || [ "$UPGRADE" = yes ]; } || {
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

# the edge group follows the role (an --upgrade without --role keeps the installed one)
if [ -z "$ROLE" ] && [ "$UPGRADE" = yes ] && [ -r /etc/pcdn/agent.conf ]; then
  ROLE="$(sed -n 's/^GROUP=//p' /etc/pcdn/agent.conf | tail -1 | tr -d "\"' \r")"
fi
case "$ROLE" in tunnel) GROUP=tunnel ;; *) GROUP=general ;; esac

# >>> pcdn bootstrap release (SPEC §23.1; edge/tests/test_wave14.py runs this block with a fake curl)
# --version, else the release the controller pins for GROUP (GET /edge/releases; 404 = an older controller
# without pinned releases: the live bundle as before). A pinned bundle is verified against its .sha256.
RELEASE=""
RCODE="$(curl -sS "${CURL_PROTO[@]}" --max-time 60 -o "$TMP/releases.json" -w '%{http_code}' \
  "$CONTROLLER/edge/releases" 2>/dev/null)" || RCODE="${RCODE:-000}"
if [ -n "$VERSION" ]; then
  if [ "$RCODE" = 404 ]; then
    echo "bootstrap: این کنترلر نسخهٔ پین‌شده ارائه نمی‌کند" >&2
    echo "bootstrap: this controller does not offer pinned releases (no /edge/releases): run without --version" >&2
    exit 1
  fi
  RELEASE="$VERSION"
elif [ "$RCODE" = 200 ]; then
  REL_JSON="$(tr -d '\r\n' < "$TMP/releases.json")"
  REL_GROUPS="$(printf '%s' "$REL_JSON" | sed -n 's/.*"groups"[[:space:]]*:[[:space:]]*{\([^}]*\)}.*/\1/p')"
  RELEASE="$(printf '%s' "$REL_GROUPS" | sed -n "s/.*\"$GROUP\"[[:space:]]*:[[:space:]]*\"\(v[0-9A-Za-z.-]*\)\".*/\1/p")"
  if [ -z "$RELEASE" ]; then
    RELEASE="$(printf '%s' "$REL_JSON" | sed -n 's/.*"pinned"[[:space:]]*:[[:space:]]*"\(v[0-9A-Za-z.-]*\)".*/\1/p')"
  fi
  [[ "$RELEASE" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || RELEASE=""
  [ -z "$RELEASE" ] || echo "==> the controller pins release $RELEASE for the $GROUP group"
fi
if [ -n "$RELEASE" ]; then
  echo "==> downloading edge release $RELEASE from $CONTROLLER"
  if ! curl -fsSL "${CURL_PROTO[@]}" "$CONTROLLER/edge/bundle.tar.gz?version=$RELEASE" -o "$TMP/bundle.tar.gz" \
     || ! curl -fsSL "${CURL_PROTO[@]}" "$CONTROLLER/edge/releases/$RELEASE.sha256" -o "$TMP/bundle.sha256"; then
    echo "bootstrap: failed to download release $RELEASE (or its .sha256) from $CONTROLLER" >&2
    echo "  - is it in the controller's EDGE_RELEASES_DIR? (GET /edge/releases lists them)" >&2
    exit 1
  fi
  SUM="$(awk 'NR == 1 {print $1}' "$TMP/bundle.sha256")"
  if ! [[ "$SUM" =~ ^[0-9a-f]{64}$ ]] \
     || ! (cd "$TMP" && printf '%s  bundle.tar.gz\n' "$SUM" | sha256sum -c --status -); then
    echo "bootstrap: sha256 mismatch for release $RELEASE: nothing installed" >&2
    exit 1
  fi
  echo "    sha256 verified ($SUM)"
else
  echo "==> downloading edge bundle from $CONTROLLER/edge/bundle.tar.gz"
  if ! curl -fsSL "${CURL_PROTO[@]}" "$CONTROLLER/edge/bundle.tar.gz" -o "$TMP/bundle.tar.gz"; then
    echo "bootstrap: failed to download the edge bundle from $CONTROLLER" >&2
    echo "  - check that the controller is reachable and EDGE_BUNDLE_DIR is configured there" >&2
    exit 1
  fi
fi
# <<< pcdn bootstrap release

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
[ -z "$RELEASE" ] || PASS+=(--release "$RELEASE")
PCDN_EDGE_TOKEN="$TOKEN" PCDN_JOIN_TOKEN="$JOIN_TOKEN" PCDN_RELEASE_TARBALL="$TMP/bundle.tar.gz" \
  ./install.sh --controller "$CONTROLLER" ${PASS[@]+"${PASS[@]}"}
