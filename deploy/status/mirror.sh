#!/bin/sh
# Public status page mirror (runs next to Caddy on a SEPARATE host — see docs/MONITORING.md).
#
# 1. Once at start: copies the static page (repo status/) into $WWW_DIR and adds mirror.js, which
#    shows a "last known state" notice when the controller cannot be reached.
# 2. Every $MIRROR_INTERVAL seconds: fetches /status.json from the first reachable upstream in
#    $STATUS_UPSTREAMS, validates it, keeps only the public fields and atomically replaces
#    $DATA_DIR/status.json. On failure the previous file is KEPT (last known state) and only
#    $DATA_DIR/mirror.json records the failure. $DATA_DIR is a volume, so the last known state
#    also survives restarts of this host.
#
# Needs: sh, curl, jq.   One-shot (cron / CI):  mirror.sh --once
set -eu

STATUS_UPSTREAMS="${STATUS_UPSTREAMS:-}"          # space separated base URLs, primary first
MIRROR_INTERVAL="${MIRROR_INTERVAL:-20}"
MIRROR_TIMEOUT="${MIRROR_TIMEOUT:-10}"
SRC_DIR="${SRC_DIR:-/src/status}"
WWW_DIR="${WWW_DIR:-/srv/www}"
DATA_DIR="${DATA_DIR:-/srv/data}"
MIRROR_JS="${MIRROR_JS:-/src/mirror.js}"
MAX_BYTES=1048576

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) mirror: $*" >&2; }

[ -n "$STATUS_UPSTREAMS" ] || { log "STATUS_UPSTREAMS is required (e.g. https://cdn-api.example.com)"; exit 1; }
for u in $STATUS_UPSTREAMS; do
  case "$u" in https://*|http://*) ;; *) log "bad upstream '$u' (must be http(s)://...)"; exit 1 ;; esac
done
case "$MIRROR_INTERVAL" in ''|*[!0-9]*) log "MIRROR_INTERVAL must be seconds"; exit 1 ;; esac
[ "$MIRROR_INTERVAL" -ge 5 ] || MIRROR_INTERVAL=5

# keep only the public fields documented in SPEC §8.2 / controller/app/status.py, with types checked
JQ_FILTER='
def str: if type == "string" then .[0:20000] else error("not a string") end;
def status_ok: . as $s | ["operational","degraded","maintenance","major_outage","partial_outage"] | index($s) != null;
if (.status | type) != "string" or ((.status | status_ok) | not) then error("bad status") else . end
| {
    status: .status,
    updated_at: (.updated_at | str),
    nodes: {total: (.nodes.total // 0 | tonumber), online: (.nodes.online // 0 | tonumber)},
    components: [(.components // [])[] | {name: (.name | str), status: (.status | str)}],
    incidents: [(.incidents // [])[] | {
      id, title: (.title | str), body: ((.body // "") | str), severity: (.severity | str),
      status: (.status | str), created_at: (.created_at | str), updated_at: (.updated_at | str),
      updates: [(.updates // [])[] | {at: (.at | str), status: (.status | str), body: ((.body // "") | str)}]
    }]
  }'

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

build_site() {
  mkdir -p "$WWW_DIR" "$DATA_DIR"
  for f in index.html status.css status.js; do
    [ -f "$SRC_DIR/$f" ] || { log "missing $SRC_DIR/$f (mount the repo's status/ directory)"; exit 1; }
  done
  tmp="$WWW_DIR/.build"
  rm -rf "$tmp" && mkdir -p "$tmp"
  cp "$SRC_DIR/status.css" "$SRC_DIR/status.js" "$tmp/"
  cp "$MIRROR_JS" "$tmp/mirror.js"
  # load mirror.js right after status.js (both deferred, so it runs after the page is parsed)
  awk '{ print } /<script src="status.js" defer><\/script>/ { print "<script src=\"mirror.js\" defer></script>" }' \
    "$SRC_DIR/index.html" > "$tmp/index.html"
  grep -q 'src="mirror.js"' "$tmp/index.html" || log "warning: could not add mirror.js to index.html"
  for f in index.html status.css status.js mirror.js; do mv "$tmp/$f" "$WWW_DIR/$f"; done
  rmdir "$tmp"
  log "site assembled in $WWW_DIR"
}

last_ok_at() {
  [ -f "$DATA_DIR/mirror.json" ] && jq -r '.last_ok_at // empty' "$DATA_DIR/mirror.json" 2>/dev/null || true
}

# mirror.json is PUBLIC: timestamps only. Upstream URLs and errors go to the log, never here.
write_meta() {  # ok last_ok_at
  jq -n --argjson ok "$1" --arg last "$2" --arg at "$(now)" --argjson interval "$MIRROR_INTERVAL" \
     '{ok: $ok, checked_at: $at, last_ok_at: (if $last == "" then null else $last end),
       interval_seconds: $interval}' \
     > "$DATA_DIR/.mirror.json.tmp"
  mv "$DATA_DIR/.mirror.json.tmp" "$DATA_DIR/mirror.json"
}

fetch_once() {
  i=0
  errs=""
  for base in $STATUS_UPSTREAMS; do
    i=$((i + 1))
    url="${base%/}/status.json"
    raw="$DATA_DIR/.raw.json"
    if curl -fsS --proto '=https,http' --max-time "$MIRROR_TIMEOUT" --max-filesize "$MAX_BYTES" \
         -H 'Accept: application/json' -A 'pcdn-status-mirror/1' -o "$raw" "$url" 2>"$DATA_DIR/.curl.err"; then
      if jq -c "$JQ_FILTER" "$raw" > "$DATA_DIR/.status.json.tmp" 2>"$DATA_DIR/.jq.err"; then
        mv "$DATA_DIR/.status.json.tmp" "$DATA_DIR/status.json"
        rm -f "$raw"
        write_meta true "$(now)"
        return 0
      fi
      errs="$errs upstream $i: invalid JSON ($(head -c 200 "$DATA_DIR/.jq.err"));"
    else
      errs="$errs upstream $i: $(head -c 200 "$DATA_DIR/.curl.err" | tr '\n' ' ');"
    fi
    rm -f "$raw" "$DATA_DIR/.status.json.tmp"
  done
  # every upstream failed: keep the last known status.json untouched
  write_meta false "$(last_ok_at)"
  log "all upstreams failed:$errs"
  return 1
}

build_site
if [ "${1:-}" = "--once" ]; then
  fetch_once
  exit $?
fi
log "mirroring every ${MIRROR_INTERVAL}s from: $STATUS_UPSTREAMS"
while :; do
  fetch_once || true
  sleep "$MIRROR_INTERVAL"
done
