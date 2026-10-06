#!/usr/bin/env bash
# Pasargad CDN — prepare a platform release (SPEC §23.1, docs/RELEASE.md)
#
#   tools/release/prepare.sh X.Y.Z[-rc.N] [--date YYYY-MM-DD]
#
# Refuses unless the working tree is clean, X.Y.Z is valid SemVer greater than VERSION (SemVer §11
# pre-release ordering) and CHANGELOG.md's [Unreleased] section is not empty. Then it moves
# [Unreleased] to "## [X.Y.Z] - <UTC date>" (merging an existing "## [X.Y.Z] - Unreleased" section),
# updates the compare links and VERSION, and PRINTS the next commands.
#
# It never commits, pushes, merges, tags or publishes anything: merging to main, creating the vX.Y.Z
# tag and publishing the GitHub release need the repository owner's explicit confirmation.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="$HERE/release_tool.py"

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; }

version="" date_arg=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --date) date_arg=(--date "${2:?--date needs YYYY-MM-DD}"); shift 2 ;;
    --date=*) date_arg=(--date "${1#--date=}"); shift ;;
    -*) echo "prepare: unknown option $1" >&2; exit 2 ;;
    *) if [ -n "$version" ]; then echo "prepare: one version only" >&2; exit 2; fi; version="${1#v}"; shift ;;
  esac
done
if [ -z "$version" ]; then usage >&2; exit 2; fi

REPO="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "prepare: run inside the git checkout" >&2; exit 1; }
if [ -n "$(git -C "$REPO" status --porcelain)" ]; then
  echo "prepare: the working tree is not clean (commit or remove the changes first):" >&2
  git -C "$REPO" status --short >&2
  exit 1
fi

current="$(head -n1 "$REPO/VERSION" 2>/dev/null || true)"
python3 "$TOOL" --repo "$REPO" prepare "$version" "${date_arg[@]}"

tag="v$version"
branch="release/$tag"
cat <<MSG

Prepared $tag (VERSION $current -> $version, CHANGELOG section [$version]).
Review:  git -C "$REPO" diff

Next steps — run them yourself; this script never commits, pushes, merges or tags:

  git switch -c $branch
  git add VERSION CHANGELOG.md
  git commit -m "Release $tag"
  git push -u origin $branch
  tools/release/changelog-section.sh $version > /tmp/pcdn-$tag-notes.md
  gh pr create --base main --head $branch --title "Release $tag" --body-file /tmp/pcdn-$tag-notes.md

Before asking the owner to merge: run the staging gate on the PR head and attach the evidence
  tools/release/staging-verify.sh --env-file deploy/staging/staging-gate.env --controller <staging URL> ...

Only after the repository owner has explicitly confirmed and merged the PR (never before):

  git fetch origin
  git tag -a $tag -m "Pasargad CDN $tag" <merge commit on origin/main>
  git push origin $tag

The tag starts .github/workflows/release-platform.yml, which tests, builds
dist/pcdn-edge-$tag.tar.gz (+ .sha256) and creates a DRAFT GitHub release; the owner publishes it.
MSG
