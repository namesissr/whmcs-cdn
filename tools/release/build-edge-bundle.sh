#!/usr/bin/env bash
# Pasargad CDN — build the pinned edge release bundle (SPEC §23.1)
#
#   tools/release/build-edge-bundle.sh vX.Y.Z [--from-tag] [--src DIR] [--out DIR]
#
# Writes <out>/pcdn-edge-vX.Y.Z.tar.gz and <out>/pcdn-edge-vX.Y.Z.tar.gz.sha256 (sha256sum format).
# Layout = the controller's live bundle (controller/app/bundle.py): top directory edge/, excludes
# __pycache__, tests, *.pyc, agent.conf; plus edge/RELEASE containing "vX.Y.Z". Deterministic: sorted
# entries, mtime = commit time of the tag (else $SOURCE_DATE_EPOCH, else HEAD), uid/gid 0, gzip -n.
#
#   --from-tag   take edge/ from the tag vX.Y.Z of this checkout (git archive), not the working tree
#   --src DIR    edge/ directory to package (default: <repo>/edge)
#   --out DIR    output directory (default: <repo>/dist)
#
# Fill the controller's EDGE_RELEASES_DIR with the two files (or use fetch-edge-release.sh).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'

tag="" from_tag=0 src="" out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --from-tag) from_tag=1; shift ;;
    --src) src="${2:?}"; shift 2 ;;
    --out) out="${2:?}"; shift 2 ;;
    -*) echo "build-edge-bundle: unknown option $1" >&2; exit 2 ;;
    *) tag="$1"; shift ;;
  esac
done
if ! printf '%s' "$tag" | grep -Eq "$TAG_RE"; then
  echo "build-edge-bundle: give the release tag vX.Y.Z[-pre]" >&2; exit 2
fi
out="${out:-$REPO/dist}"

tmp=""
cleanup() { if [ -n "$tmp" ]; then rm -rf "$tmp"; fi; }
trap cleanup EXIT

if [ "$from_tag" = 1 ]; then
  if ! git -C "$REPO" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    echo "build-edge-bundle: tag $tag does not exist in this checkout (git fetch --tags)" >&2; exit 1
  fi
  tmp="$(mktemp -d)"
  git -C "$REPO" archive --format=tar "$tag" edge | tar -x -C "$tmp"
  src="$tmp/edge"
  mtime="$(git -C "$REPO" log -1 --format=%ct "$tag^{commit}")"
else
  src="${src:-$REPO/edge}"
  if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    mtime="$SOURCE_DATE_EPOCH"
  elif git -C "$REPO" rev-parse -q --verify "refs/tags/$tag" >/dev/null 2>&1; then
    mtime="$(git -C "$REPO" log -1 --format=%ct "$tag^{commit}")"
  else
    mtime="$(git -C "$REPO" log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
  fi
fi

if [ "$out" = "$REPO/dist" ] && [ ! -e "$out/.gitignore" ]; then
  mkdir -p "$out" && printf '# build output, never committed\n*\n' > "$out/.gitignore"
fi
python3 "$HERE/release_tool.py" --repo "$REPO" bundle "$tag" --src "$src" --out "$out" --mtime "$mtime"
