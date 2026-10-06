#!/usr/bin/env bash
# Pasargad CDN — download a published edge release into the controller's EDGE_RELEASES_DIR (SPEC §23.1)
#
#   tools/release/fetch-edge-release.sh vX.Y.Z --dir <EDGE_RELEASES_DIR> [--repo OWNER/NAME] [--base-url URL]
#
# Downloads pcdn-edge-vX.Y.Z.tar.gz and its .sha256 from the GitHub release (default repository
# namesissr/whmcs-cdn; --base-url overrides the download directory, e.g. a mirror), verifies the
# checksum and moves both files into --dir. An existing file with the same name but different
# content is never replaced (exit 1); an identical one is left as is (exit 0).
set -euo pipefail

TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
tag="" dir="" repo="namesissr/whmcs-cdn" base=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --dir) dir="${2:?}"; shift 2 ;;
    --repo) repo="${2:?}"; shift 2 ;;
    --base-url) base="${2:?}"; shift 2 ;;
    -*) echo "fetch-edge-release: unknown option $1" >&2; exit 2 ;;
    *) tag="$1"; shift ;;
  esac
done
if ! printf '%s' "$tag" | grep -Eq "$TAG_RE"; then echo "fetch-edge-release: give the tag vX.Y.Z" >&2; exit 2; fi
if [ -z "$dir" ]; then echo "fetch-edge-release: --dir <EDGE_RELEASES_DIR> is required" >&2; exit 2; fi
if ! printf '%s' "$repo" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'; then
  echo "fetch-edge-release: --repo must be OWNER/NAME" >&2; exit 2
fi
base="${base:-https://github.com/$repo/releases/download/$tag}"
base="${base%/}"

# https only; plain http is accepted for a loopback mirror (tests / a local cache)
proto=(--proto '=https' --tlsv1.2)
case "$base" in
  https://*) ;;
  http://127.0.0.1[:/]*|http://localhost[:/]*|http://\[::1\][:/]*) proto=() ;;
  *) echo "fetch-edge-release: --base-url must be https:// (http only for localhost)" >&2; exit 2 ;;
esac

name="pcdn-edge-$tag.tar.gz"
mkdir -p "$dir"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL "${proto[@]}" --max-filesize 52428800 -o "$tmp/$name" "$base/$name"
curl -fsSL "${proto[@]}" --max-filesize 4096 -o "$tmp/$name.sha256" "$base/$name.sha256"

read -r want fname _ < "$tmp/$name.sha256" || true
fname="${fname#\*}"
if ! printf '%s' "$want" | grep -Eq '^[0-9a-f]{64}$' || [ "$fname" != "$name" ]; then
  echo "fetch-edge-release: $name.sha256 is not '<sha256>  $name'" >&2; exit 1
fi
( cd "$tmp" && sha256sum -c --status "$name.sha256" ) || {
  echo "fetch-edge-release: sha256 mismatch for $name — nothing installed" >&2; exit 1; }

if [ -e "$dir/$name" ]; then
  have="$(sha256sum "$dir/$name" | cut -d' ' -f1)"
  if [ "$have" != "$want" ]; then
    echo "fetch-edge-release: $dir/$name exists with different content ($have); refusing to replace it" >&2
    exit 1
  fi
  echo "already present: $dir/$name ($want)"
  if [ ! -e "$dir/$name.sha256" ]; then install -m 0644 "$tmp/$name.sha256" "$dir/$name.sha256"; fi
  exit 0
fi
install -m 0644 "$tmp/$name.sha256" "$dir/$name.sha256.tmp"
install -m 0644 "$tmp/$name" "$dir/$name.tmp"
mv -f "$dir/$name.tmp" "$dir/$name"
mv -f "$dir/$name.sha256.tmp" "$dir/$name.sha256"
echo "installed: $dir/$name ($want)"
