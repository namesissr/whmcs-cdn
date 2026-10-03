#!/usr/bin/env bash
# STAGING ONLY — edge container entrypoint.
#
# First start: wait for the token the runner minted through the admin API (POST /api/v1/edges), then
# run the controller-provided install one-liner exactly as an operator would on a fresh server:
#     curl -fsSL <controller>/edge/bootstrap.sh | sudo PCDN_EDGE_TOKEN=edge_... bash -s -- --controller <controller> ...
# with two staging adjustments: the controller is reached over plain HTTP on the internal network
# (the one-liner says https://<CONTROLLER_DOMAIN>; EDGE_INSTALL_FLAGS carries --insecure-http, which
# bootstrap.sh requires for an http:// controller), and `sudo` is dropped (the container runs as
# root, and sudo would strip the PCDN_* overrides from the environment). The token is taken out of
# the one-liner and exported as PCDN_EDGE_TOKEN (what `sudo PCDN_EDGE_TOKEN=... bash` does), so it is
# not on any command line. EDGE_INSTALL_FLAGS are appended (bootstrap.sh passes them to install.sh).
# Every start: make sure nginx runs, then exec the agent in the foreground (what pcdn-agent.service does).
set -euo pipefail

: "${EDGE_NAME:?EDGE_NAME is required}"
TOKENS_DIR="${TOKENS_DIR:-/staging/tokens}"
CONTROLLER_URL="${CONTROLLER_URL:-http://controller:8000}"
CONTROLLER_PUBLIC_URL="${CONTROLLER_PUBLIC_URL:-https://controller:8000}"
EDGE_INSTALL_FLAGS="${EDGE_INSTALL_FLAGS:-}"
WAIT_SECONDS="${TOKEN_WAIT_SECONDS:-600}"

MARK=/var/lib/pcdn/.staging-installed   # written only after install.sh succeeded
if [ ! -f "$MARK" ]; then
  tf="$TOKENS_DIR/$EDGE_NAME.json"
  echo "==> staging edge $EDGE_NAME: waiting for $tf"
  for _ in $(seq 1 "$WAIT_SECONDS"); do [ -s "$tf" ] && break; sleep 1; done
  [ -s "$tf" ] || { echo "no token file for $EDGE_NAME after ${WAIT_SECONDS}s" >&2; exit 1; }

  install="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["install"])' "$tf")"
  redacted="$(sed -E 's/edge_[A-Za-z0-9_-]+/edge_<redacted>/g' <<<"$install")"
  prefix="curl -fsSL $CONTROLLER_PUBLIC_URL/edge/bootstrap.sh | sudo PCDN_EDGE_TOKEN="
  case "$install" in
    "$prefix"*" bash -s -- "*) ;;
    *) echo "unexpected install one-liner from the controller: $redacted" >&2; exit 1 ;;
  esac
  rest="${install#"$prefix"}"          # <token> bash -s -- --controller ...
  token="${rest%% *}"                  # the controller's token is shell-safe (edge_ + urlsafe base64)
  case "$token" in edge_*) ;; *) echo "unexpected token in the install one-liner: $redacted" >&2; exit 1 ;; esac
  cmd="curl -fsSL $CONTROLLER_PUBLIC_URL/edge/bootstrap.sh | ${rest#* }"
  cmd="${cmd//"$CONTROLLER_PUBLIC_URL"/"$CONTROLLER_URL"}"
  cmd="$cmd $EDGE_INSTALL_FLAGS"
  echo "==> staging edge $EDGE_NAME: PCDN_EDGE_TOKEN=edge_<redacted> $cmd"
  PCDN_EDGE_TOKEN="$token" bash -o pipefail -c "$cmd"
  mkdir -p "$(dirname "$MARK")" && date -u +%FT%TZ > "$MARK"
  echo "==> staging edge $EDGE_NAME: installed"
else
  echo "==> staging edge $EDGE_NAME: already installed, starting services"
fi

systemctl start nginx
if [ -f /etc/pcdn/imaged.conf ] && /usr/bin/python3 -c 'import PIL' 2>/dev/null; then
  systemctl start pcdn-imaged || true
fi

export PCDN_CONFIG=/etc/pcdn/agent.conf
echo "==> staging edge $EDGE_NAME: pcdn-agent in the foreground"
exec /usr/bin/python3 /usr/local/bin/pcdn-agent
