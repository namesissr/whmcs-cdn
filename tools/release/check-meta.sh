#!/usr/bin/env bash
# Release metadata checks run by CI (job release-meta, SPEC §23.1):
#   1. VERSION is valid SemVer (X.Y.Z[-pre]) and CHANGELOG.md has "## [Unreleased]"
#   2. build-edge-bundle.sh is deterministic (two builds -> identical sha256)
#   3. bash -n + shellcheck (when installed) of tools/release/*.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

python3 "$HERE/release_tool.py" --repo "$REPO" check-meta

tag="v$(head -n1 "$REPO/VERSION")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
"$HERE/build-edge-bundle.sh" "$tag" --out "$tmp/a" >/dev/null
sleep 1   # a wall-clock timestamp leaking into the archive would now differ
"$HERE/build-edge-bundle.sh" "$tag" --out "$tmp/b" >/dev/null
a="$(cut -d' ' -f1 "$tmp/a/pcdn-edge-$tag.tar.gz.sha256")"
b="$(cut -d' ' -f1 "$tmp/b/pcdn-edge-$tag.tar.gz.sha256")"
if [ "$a" != "$b" ]; then echo "release-meta: edge bundle is not deterministic ($a != $b)" >&2; exit 1; fi
( cd "$tmp/a" && sha256sum -c --quiet "pcdn-edge-$tag.tar.gz.sha256" )
if ! tar -xzOf "$tmp/a/pcdn-edge-$tag.tar.gz" edge/RELEASE | grep -qx "$tag"; then
  echo "release-meta: edge/RELEASE missing or wrong in the bundle" >&2; exit 1
fi
echo "edge bundle deterministic: $a"

for f in "$HERE"/*.sh "$REPO"/tools/provision/*.sh; do
  [ -e "$f" ] || continue
  bash -n "$f"
done
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -x "$HERE"/*.sh
  echo "shellcheck ok"
else
  echo "note: shellcheck not installed; only bash -n was run"
fi
