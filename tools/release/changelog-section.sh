#!/usr/bin/env bash
# Print the body of one CHANGELOG.md section (release notes; used by release-platform.yml).
#   tools/release/changelog-section.sh X.Y.Z|vX.Y.Z|Unreleased
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ $# -ne 1 ]; then echo "usage: $0 X.Y.Z|Unreleased" >&2; exit 2; fi
REPO="${PCDN_REPO:-$(cd "$HERE/../.." && pwd)}"
exec python3 "$HERE/release_tool.py" --repo "$REPO" section "$1"
