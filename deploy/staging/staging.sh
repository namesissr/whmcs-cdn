#!/usr/bin/env bash
# Pasargad CDN — one-command staging environment (docs/STAGING.md)
#
#   deploy/staging/staging.sh up            build + start everything, wait until healthy
#   deploy/staging/staging.sh test [args]   run tests/integration inside the runner (pytest args pass through)
#   deploy/staging/staging.sh ci            up + test, logs on failure, always down (what CI runs)
#   deploy/staging/staging.sh logs [dir]    service logs + edge diagnostics (to stdout, or files in dir)
#   deploy/staging/staging.sh down          stop and remove containers, network and volumes
#   deploy/staging/staging.sh config        validate the compose file
#   deploy/staging/staging.sh ps | compose <args...>
#
# Environment: STAGING_STORAGE=1 adds MinIO (profile "storage") and the storage-origin test;
# STAGING_NET=a.b.c changes the /24 (default 11.200.0); STAGING_WAIT_TIMEOUT (s, default 900).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$HERE/compose.yml")

# the controller reports this as its version (/healthz, SPEC §23.1)
if [ -z "${PCDN_VERSION:-}" ] && [ -f "$HERE/../../VERSION" ]; then
  PCDN_VERSION="$(head -n1 "$HERE/../../VERSION")"
  export PCDN_VERSION
fi

if [ "${STAGING_STORAGE:-0}" = 1 ]; then
  export STAGING_STORAGE=1
  export STAGING_STORAGE_ENDPOINT="${STAGING_STORAGE_ENDPOINT:-http://seaweedfs:9000}"
  # must match deploy/staging/seaweed-s3.json (public, staging-only values)
  export STAGING_STORAGE_ACCESS_KEY="${STAGING_STORAGE_ACCESS_KEY:-STAGINGCONTROLLERKEY}"
  export STAGING_STORAGE_SECRET_KEY="${STAGING_STORAGE_SECRET_KEY:-staging-storage-secret}"
  COMPOSE+=(--profile storage)
fi

EDGES=(edge-1 edge-2)

dump_logs() {
  local dir="${1:-}"
  if [ -n "$dir" ]; then mkdir -p "$dir"; fi
  to() { if [ -n "$dir" ]; then echo "$dir/$1"; else echo /dev/stdout; fi; }
  section() { echo; echo "==================== $* ===================="; }
  {
    section "docker compose ps"
    "${COMPOSE[@]}" ps -a || true
  } > "$(to ps.txt)" 2>&1
  for svc in $("${COMPOSE[@]}" config --services 2>/dev/null); do
    {
      section "logs: $svc"
      "${COMPOSE[@]}" logs --no-color --timestamps "$svc" 2>&1 | tail -n "${STAGING_LOG_LINES:-400}" || true
    } > "$(to "$svc.log")" 2>&1
  done
  for e in "${EDGES[@]}"; do
    {
      section "$e: nginx error.log"
      "${COMPOSE[@]}" exec -T "$e" tail -n 200 /var/log/nginx/error.log 2>&1 || true
      section "$e: agent.conf (token redacted)"
      "${COMPOSE[@]}" exec -T "$e" sed -E 's/^(EDGE_TOKEN=).*/\1<redacted>/' /etc/pcdn/agent.conf 2>&1 || true
      section "$e: nginx -T (first 300 lines)"
      "${COMPOSE[@]}" exec -T "$e" sh -c 'nginx -T 2>&1 | head -n 300' 2>&1 || true
    } > "$(to "$e-diag.txt")" 2>&1
  done
  {
    section "controller: GET /api/v1/edges"
    # shellcheck disable=SC2016  # expanded inside the runner, which holds the key
    "${COMPOSE[@]}" exec -T runner sh -c \
      'curl -sS -H "Authorization: Bearer $ADMIN_API_KEY" "$CONTROLLER_URL/api/v1/edges"' 2>&1 || true
  } > "$(to edges.json)" 2>&1
}

cmd="${1:-help}"
shift || true
case "$cmd" in
  up)
    if ! "${COMPOSE[@]}" up -d --build --wait --wait-timeout "${STAGING_WAIT_TIMEOUT:-900}"; then
      echo "staging: the stack did not become healthy" >&2
      dump_logs
      exit 1
    fi
    "${COMPOSE[@]}" ps
    ;;
  test)
    "${COMPOSE[@]}" exec -T -e "STAGING_STORAGE=${STAGING_STORAGE:-0}" runner \
      python -m pytest -c /tests/integration/pytest.ini /tests/integration "$@"
    ;;
  ci)
    rc=0
    "$0" up || rc=$?
    if [ "$rc" = 0 ]; then "$0" test "$@" || rc=$?; fi
    if [ "$rc" != 0 ]; then dump_logs "${STAGING_LOG_DIR:-}"; fi
    "$0" down || true
    exit "$rc"
    ;;
  logs) dump_logs "${1:-}" ;;
  down) "${COMPOSE[@]}" down -v --remove-orphans ;;
  config) "${COMPOSE[@]}" config -q && echo "compose config OK" ;;
  ps) "${COMPOSE[@]}" ps -a ;;
  compose) "${COMPOSE[@]}" "$@" ;;
  *) sed -n '2,15p' "$0"; [ "$cmd" = help ] || exit 2 ;;
esac
