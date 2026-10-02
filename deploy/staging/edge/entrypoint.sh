#!/usr/bin/env bash
# STAGING ONLY — edge container entrypoint.
#
# First start: wait for the token the runner minted through the admin API (POST /api/v1/edges), then
# run the controller-provided install one-liner exactly as an operator would on a fresh server:
#     curl -fsSL <controller>/edge/bootstrap.sh | sudo bash -s -- --controller <controller> --token edge_...
# with two staging adjustments: the controller is reached over plain HTTP on the internal network
# (the one-liner says https://<CONTROLLER_DOMAIN>), and `sudo` is dropped (the container runs as root,
# and sudo would strip the PCDN_* cadence overrides from the environment). EDGE_INSTALL_FLAGS are
# appended (bootstrap.sh passes them through to install.sh).
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
  case "$install" in
    "curl -fsSL $CONTROLLER_PUBLIC_URL/edge/bootstrap.sh | sudo bash -s -- "*) ;;
    *) echo "unexpected install one-liner from the controller: ${install//edge_*/edge_<redacted>}" >&2; exit 1 ;;
  esac
  cmd="${install//"$CONTROLLER_PUBLIC_URL"/"$CONTROLLER_URL"}"
  cmd="${cmd/| sudo bash /| bash }"
  cmd="$cmd $EDGE_INSTALL_FLAGS"
  echo "==> staging edge $EDGE_NAME: $(sed -E 's/edge_[A-Za-z0-9_-]+/edge_<redacted>/g' <<<"$cmd")"
  bash -o pipefail -c "$cmd"
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
