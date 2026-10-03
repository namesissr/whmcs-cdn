#!/bin/sh
# Create (or re-apply) the controller's MinIO user + policy (SPEC §16.8, docs/STORAGE.md).
# Run on the storage server, next to .env:   ./bootstrap.sh            (single node)
#                                            ./bootstrap.sh -f docker-compose.erasure.yml
# Prints STORAGE_ADMIN_ACCESS_KEY / STORAGE_ADMIN_SECRET_KEY ONCE for the controller's .env.
# Re-running keeps the user and only re-applies the policy, unless --rotate is given (new secret).
set -eu
cd "$(dirname "$0")"
COMPOSE="docker compose"
ROTATE=0
while [ $# -gt 0 ]; do
  case "$1" in
    -f) COMPOSE="$COMPOSE -f $2"; shift 2 ;;
    --rotate) ROTATE=1; shift ;;
    *) echo "usage: $0 [-f compose-file] [--rotate]" >&2; exit 2 ;;
  esac
done
[ -f .env ] || { echo ".env missing: cp .env.example .env and edit it" >&2; exit 1; }
USER_NAME=$(grep -E '^PCDN_CONTROLLER_USER=' .env | cut -d= -f2-)
USER_NAME=${USER_NAME:-pcdn-controller}
PCDN_SECRET=
export PCDN_SECRET

mc() { $COMPOSE --profile tools run --rm -T -e PCDN_SECRET mc -c "$1"; }

mc "mc admin policy create local pcdn-controller /policy/pcdn-controller-policy.json"
if mc "mc admin user info local '$USER_NAME'" >/dev/null 2>&1 && [ "$ROTATE" = 0 ]; then
  mc "mc admin policy attach local pcdn-controller --user '$USER_NAME'" 2>/dev/null || true
  echo "user $USER_NAME exists; policy re-applied (use --rotate for a new secret)"
  exit 0
fi
PCDN_SECRET=$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-40)
export PCDN_SECRET
# the secret reaches the throwaway mc container as an environment variable (not on this host's
# command line, never written to a file)
mc "mc admin user add local '$USER_NAME' \"\$PCDN_SECRET\""
mc "mc admin policy attach local pcdn-controller --user '$USER_NAME'" 2>/dev/null || true
echo
echo "Put these into the CONTROLLER's .env (not this server's), then restart the controller:"
echo "  STORAGE_ADMIN_ACCESS_KEY=$USER_NAME"
echo "  STORAGE_ADMIN_SECRET_KEY=$PCDN_SECRET"
