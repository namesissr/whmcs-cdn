#!/usr/bin/env bash
# Pasargad CDN — staging verification gate before a release (SPEC §23.1, docs/RELEASE.md)
#
#   tools/release/staging-verify.sh --env-file deploy/staging/staging-gate.env --controller <staging URL> \
#       [--ns ns1:53 ...] [--edge-target IP:port --loadtest-host HOST] [--skip-<step>] [--out DIR]
#
# Steps: version, preflight, migrations, integration, loadtest, backup, rollout (dry run), security.
# Evidence: <out>/vX.Y.Z/{report.md,report.json,raw/} (default release-evidence/, git-ignored).
# Exit: 0 PASS, 1 FAIL, 2 refused (production controller / usage), 3 PARTIAL (a step was skipped).
# Never runs against production: a controller listed in PCDN_PROD_CONTROLLERS or reporting
# "environment": "production" is refused (no override). Run with --help for every option.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/staging_verify.py" "$@"
