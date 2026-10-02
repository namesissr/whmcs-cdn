#!/usr/bin/env bash
# shellcheck disable=SC2317  # the do_* phase functions and teardown are called indirectly
# Disaster-recovery drill: restore the latest encrypted backup into a THROWAWAY stack and prove it works.
#
#   tools/drill/dr-drill.sh --env-file /secure/pcdn.env [--backup latest|FILE|s3:KEY] [--backup-dir DIR]
#                           [--edge-token TOKEN ...] [--edge-tokens-file FILE] [--sample-zone ZONE]
#                           [--project pcdn-drill] [--image pcdn-controller:local] [--report-dir DIR]
#                           [--keep] [--replace] [--allow-prod-host] [--dry-run]
#
# Run it on a SCRATCH host (or a scratch VM) with Docker + compose v2. It:
#   1. fetches the backup (newest in --backup-dir, else newest in BACKUP_S3_* of the env file) - read only
#   2. reads the expected state from the dump inside the archive (sites, records, edge tokens, DNSSEC)
#   3. starts PostgreSQL 16, restores controller DB + PowerDNS DB + acme.sh home (manage restore),
#      which migrates to head, then starts PowerDNS and the controller            -> RTO ends here
#   4. verifies: migrations at head, site/record counts and edge tokens match the dump, secrets
#      decrypt, edge config builds and edges fetch it with existing tokens, zones + DNSSEC keys in
#      PowerDNS, a sample zone answers over DNS (DNSKEY/RRSIG when signed), acme home present
#   5. writes report.md / report.json (PASS/FAIL, per-phase timings, RTO, backup age = RPO) and
#      removes the drill stack and its volumes (unless --keep).
#
# Non-destructive: it only ever creates / removes objects of its own compose project, labelled
# pcdn.drill=1, on an internal network with no published ports and no route out (see
# drill-compose.yml). It refuses the production project name (pcdn, or PCDN_PROD_PROJECTS), a
# project name without "drill", any project containing objects it did not create, and - unless
# --allow-prod-host - a host where the production stack is running.
#
# Exit status: 0 = drill passed, 1 = drill failed (see the report), 2 = refused / usage error.
# Docs: docs/DISASTER_RECOVERY.md (Persian), section «تمرین ماهانهٔ بازیابی».
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

PROJECT="pcdn-drill"
IMAGE="pcdn-controller:local"
ENV_FILE=""
BACKUP="latest"
BACKUP_DIR=""
REPORT_DIR=""
SAMPLE_ZONE=""
TOKENS_FILE=""
KEEP=0
REPLACE=0
ALLOW_PROD_HOST=0
DRY_RUN=0
TIMEOUT="${DRILL_TIMEOUT:-300}"
PROD_PROJECTS="${PCDN_PROD_PROJECTS:-pcdn}"
EDGE_TOKENS=()

die() { echo "dr-drill: $*" >&2; exit 2; }
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

usage() { sed -n '3,28p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --env-file) ENV_FILE="${2:?}"; shift 2 ;;
    --backup) BACKUP="${2:?}"; shift 2 ;;
    --backup-dir) BACKUP_DIR="${2:?}"; shift 2 ;;
    --project) PROJECT="${2:?}"; shift 2 ;;
    --image) IMAGE="${2:?}"; shift 2 ;;
    --report-dir) REPORT_DIR="${2:?}"; shift 2 ;;
    --sample-zone) SAMPLE_ZONE="${2:?}"; shift 2 ;;
    --edge-token) EDGE_TOKENS+=("${2:?}"); shift 2 ;;
    --edge-tokens-file) TOKENS_FILE="${2:?}"; shift 2 ;;
    --timeout) TIMEOUT="${2:?}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --replace) REPLACE=1; shift ;;
    --allow-prod-host) ALLOW_PROD_HOST=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

# ------------------------------------------------------------------ guards (before touching anything)

[ -n "$ENV_FILE" ] || die "--env-file is required: a copy of production's .env (DATA_ENCRYPTION_KEY, BACKUP_PASSPHRASE, BACKUP_S3_*)"
[ -r "$ENV_FILE" ] || die "cannot read $ENV_FILE"
ENV_FILE="$(cd "$(dirname "$ENV_FILE")" && pwd)/$(basename "$ENV_FILE")"

[[ "$PROJECT" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "invalid compose project name: $PROJECT"
[[ "$PROJECT" == *drill* ]] || die "refusing project '$PROJECT': a drill project name must contain 'drill'"
IFS=', ' read -r -a _prod <<< "$PROD_PROJECTS"
_env_project="$(sed -n 's/^[[:space:]]*COMPOSE_PROJECT_NAME=//p' "$ENV_FILE" | tail -n1 | tr -d "\"'")"
for p in "${_prod[@]}" "$_env_project"; do
  [ -n "$p" ] && [ "$PROJECT" = "$p" ] && die "refusing to run against the production compose project '$p'"
done

env_value() { sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | tail -n1 | tr -d "\"'"; }
[ -n "$(env_value DATA_ENCRYPTION_KEY)" ] || log "WARNING: DATA_ENCRYPTION_KEY is empty in $ENV_FILE: encrypted secrets will not decrypt"
[ -n "$(env_value BACKUP_PASSPHRASE)" ] || log "WARNING: BACKUP_PASSPHRASE is empty in $ENV_FILE: only an unencrypted backup can be restored"

command -v docker >/dev/null || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
# the guards below ask Docker what exists: they must never "pass" because Docker did not answer
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable"

# backup source: a local file -> mount its directory read-only
SOURCE="$BACKUP"
if [ "$BACKUP" != "latest" ] && [[ "$BACKUP" != s3:* ]]; then
  if [ -f "$BACKUP" ]; then
    BACKUP_DIR="$(cd "$(dirname "$BACKUP")" && pwd)"
    SOURCE="$(basename "$BACKUP")"
  elif [ -n "$BACKUP_DIR" ] && [ -f "$BACKUP_DIR/$BACKUP" ]; then
    SOURCE="$BACKUP"
  else
    die "backup file not found: $BACKUP"
  fi
fi
[ -z "$BACKUP_DIR" ] || [ -d "$BACKUP_DIR" ] || die "--backup-dir $BACKUP_DIR is not a directory"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_DIR="${REPORT_DIR:-$PWD/drill-reports/$STAMP}"

DC=(docker compose -p "$PROJECT" -f "$HERE/drill-compose.yml" --project-directory "$HERE")

# objects of the project that were NOT created by a drill (no pcdn.drill=1 label)
foreign_objects() {
  local id lbl
  while read -r id lbl; do
    [ -n "$id" ] && [ "$lbl" != "1" ] && echo "container $id"
  done < <(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --format '{{.ID}} {{.Label "pcdn.drill"}}')
  while read -r id; do
    [ -z "$id" ] && continue
    lbl="$(docker volume inspect -f '{{index .Labels "pcdn.drill"}}' "$id" 2>/dev/null || true)"
    [ "$lbl" != "1" ] && echo "volume $id"
  done < <(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")
  return 0
}

guard_project() {
  local foreign
  foreign="$(foreign_objects)"
  [ -z "$foreign" ] || die "project '$PROJECT' contains objects not created by a drill - refusing to touch it:
$foreign"
}

guard_project
for p in "${_prod[@]}" "$_env_project"; do
  [ -z "$p" ] && continue
  if [ -n "$(docker ps -q --filter "label=com.docker.compose.project=$p")" ] && [ "$ALLOW_PROD_HOST" != 1 ]; then
    die "the production stack '$p' is running on this host. Run the drill on a scratch host, or pass
--allow-prod-host (the drill stays isolated: own volumes, internal network, no published ports)"
  fi
done
if [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")" ]; then
  [ "$REPLACE" = 1 ] || die "a previous drill '$PROJECT' still exists (--keep?). Remove it with --replace, or use --project"
fi

if [ "$DRY_RUN" = 1 ]; then
  cat <<EOF
dr-drill (dry run) - nothing was started
  project      : $PROJECT  (production names refused: ${PROD_PROJECTS}${_env_project:+, $_env_project})
  image        : $IMAGE $(docker image inspect "$IMAGE" >/dev/null 2>&1 && echo "(present)" || echo "(missing: would build $REPO/controller)")
  env file     : $ENV_FILE
  backup       : $SOURCE ${BACKUP_DIR:+(from $BACKUP_DIR)}$( [ "$SOURCE" = latest ] && [ -z "$BACKUP_DIR" ] && echo "(newest in BACKUP_S3_*)")
  edge tokens  : $(( ${#EDGE_TOKENS[@]} )) on the command line${TOKENS_FILE:+, file $TOKENS_FILE}
  report dir   : $REPORT_DIR
  keep stack   : $([ "$KEEP" = 1 ] && echo yes || echo "no (down -v of $PROJECT only)")
EOF
  exit 0
fi

# ------------------------------------------------------------------ run

mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pcdn-drill.XXXXXX")"
chmod 700 "$WORK"
EMPTY_BACKUPS="$WORK/no-local-backups"
mkdir -p "$EMPTY_BACKUPS"
PHASES="$REPORT_DIR/phases.tsv"
: > "$PHASES"

if [ -n "$TOKENS_FILE" ]; then
  [ -r "$TOKENS_FILE" ] || die "cannot read $TOKENS_FILE"
  cat "$TOKENS_FILE" > "$WORK/edge-tokens"
fi
for t in "${EDGE_TOKENS[@]+"${EDGE_TOKENS[@]}"}"; do printf '%s\n' "$t" >> "$WORK/edge-tokens"; done
[ -f "$WORK/edge-tokens" ] && chmod 600 "$WORK/edge-tokens"

rand() { od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }
DRILL_DB_PASSWORD="$(rand)"
DRILL_PDNS_KEY="$(rand)"
export DRILL_IMAGE="$IMAGE" DRILL_ENV_FILE="$ENV_FILE" DRILL_DB_PASSWORD DRILL_PDNS_KEY \
       DRILL_BACKUP_DIR="${BACKUP_DIR:-$EMPTY_BACKUPS}" DRILL_WORK="$WORK" DRILL_REPORT="$REPORT_DIR" \
       DRILL_TOOLS="$HERE" DRILL_PDNS_CONF="$REPO/dns/pdns.conf"

TOOLS=("${DC[@]}" --profile tools run --rm --no-deps -T tools)
FAILED=""

teardown() {
  local rc=$?
  if [ "$KEEP" = 1 ]; then
    log "--keep: the drill stack '$PROJECT' is left running; remove it with: docker compose -p $PROJECT down -v"
  elif [ -z "$(foreign_objects)" ]; then
    log "removing the drill stack '$PROJECT' and its volumes"
    "${DC[@]}" --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
  else
    log "NOT removing '$PROJECT': it contains objects the drill did not create"
  fi
  rm -rf "$WORK"
  exit "$rc"
}
trap teardown EXIT
trap 'exit 130' INT TERM

now() { date +%s.%N; }

# phase NAME RTO(1|0) command...: time it, record it; a failed phase stops the remaining ones
phase() {
  local name="$1" rto="$2" t0 t1 status=ok
  shift 2
  if [ -n "$FAILED" ]; then
    printf '%s\tskipped\t0\t%s\n' "$name" "$rto" >> "$PHASES"
    return 0
  fi
  log "== $name"
  t0="$(now)"
  if ! "$@"; then status=fail; FAILED="$name"; fi
  t1="$(now)"
  printf '%s\t%s\t%s\t%s\n' "$name" "$status" "$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f", b-a}')" "$rto" >> "$PHASES"
  [ "$status" = ok ] || log "phase $name FAILED"
}

wait_healthy() {  # wait_healthy SERVICE
  local svc="$1" cid state deadline=$(( $(date +%s) + TIMEOUT ))
  while :; do
    cid="$("${DC[@]}" ps -q "$svc" 2>/dev/null || true)"
    state="$( [ -n "$cid" ] && docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo starting)"
    # services with a healthcheck must be "healthy"; PowerDNS has none, "running" is enough
    if [ "$state" = healthy ] || { [ "$state" = running ] && [ "$svc" = pdns ]; }; then return 0; fi
    [ "$(date +%s)" -lt "$deadline" ] || { echo "$svc not healthy after ${TIMEOUT}s (state: $state)" >&2; "${DC[@]}" logs --tail 50 "$svc" >&2 || true; return 1; }
    sleep 2
  done
}

do_image() {
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then return 0; fi
  log "image $IMAGE missing: building it from $REPO/controller"
  docker build -t "$IMAGE" "$REPO/controller"
}

ARCHIVE=""
do_fetch() {
  local out
  out="$("${TOOLS[@]}" python /drill/drill_check.py fetch --source "$SOURCE" --backup-dir /backups --out /work)" || return 1
  ARCHIVE="$(printf '%s\n' "$out" | tail -n1)"
  if [ -z "$ARCHIVE" ] || [ ! -f "$WORK/$ARCHIVE" ]; then echo "fetch produced no archive" >&2; return 1; fi
  log "backup: $ARCHIVE ($(wc -c < "$WORK/$ARCHIVE") bytes)"
}

do_expected() {
  "${TOOLS[@]}" python /drill/drill_check.py expected --archive "/work/$ARCHIVE" --out /report/expected.json
}

do_db() { "${DC[@]}" up -d db && wait_healthy db; }

do_restore() {
  local args=(--yes)
  grep -q '"has_pdns": true' "$REPORT_DIR/expected.json" && args+=(--pdns /pdns-data/pdns.sqlite3)
  grep -q '"has_acme": true' "$REPORT_DIR/expected.json" && args+=(--acme /data/acme)
  # restore runs the migrations to head; PowerDNS runs as uid 953 in the official image
  # shellcheck disable=SC2016  # $0 / $@ are expanded by the container's sh
  "${TOOLS[@]}" sh -c 'python -m app.manage restore "/work/$0" "$@" && (chown -R 953:953 /pdns-data 2>/dev/null || true)' \
    "$ARCHIVE" "${args[@]}"
}

do_services() {
  "${DC[@]}" up -d pdns controller && wait_healthy pdns && wait_healthy controller
}

do_verify() {
  local args=(--expected /report/expected.json --pdns-db /pdns-data/pdns.sqlite3 --acme /data/acme
              --controller http://controller:8000 --pdns-api http://pdns:8081 --pdns-key "$DRILL_PDNS_KEY"
              --dns-server pdns --out /report/checks.json)
  [ -n "$SAMPLE_ZONE" ] && args+=(--sample-zone "$SAMPLE_ZONE")
  [ -f "$WORK/edge-tokens" ] && args+=(--edge-tokens-file /work/edge-tokens)
  "${TOOLS[@]}" python /drill/drill_check.py check "${args[@]}"
}

START="$(now)"
log "DR drill '$PROJECT' -> report in $REPORT_DIR"
if [ "$REPLACE" = 1 ]; then "${DC[@]}" --profile tools down -v --remove-orphans >/dev/null 2>&1 || true; fi
phase image    1 do_image
phase fetch    1 do_fetch
phase expected 1 do_expected
phase db       1 do_db
phase restore  1 do_restore
phase services 1 do_services
phase verify   0 do_verify
# a failed verification is reported through the checks, not as a skipped report
[ "$FAILED" = verify ] && FAILED=""

RC=0
if command -v python3 >/dev/null 2>&1; then
  python3 "$HERE/drill_check.py" report --phases "$PHASES" --checks "$REPORT_DIR/checks.json" \
    --expected "$REPORT_DIR/expected.json" --out "$REPORT_DIR" || RC=1
else
  "${TOOLS[@]}" python /drill/drill_check.py report --phases /report/phases.tsv --checks /report/checks.json \
    --expected /report/expected.json --out /report || RC=1
fi
log "drill finished in $(awk -v a="$START" -v b="$(now)" 'BEGIN{printf "%.1f", b-a}')s: $([ "$RC" = 0 ] && echo PASS || echo FAIL) - $REPORT_DIR/report.md"
exit "$RC"
