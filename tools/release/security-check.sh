#!/usr/bin/env bash
# Pasargad CDN — automated part of the release security review (SPEC §23.1, docs/RELEASE.md)
#
#   tools/release/security-check.sh [--since REF] [--repo DIR] [--template-only]
#
# Checks (exit 1 when any FAILs; tools that are not installed are reported SKIP):
#   secrets      gitleaks detect (when installed) else the built-in regex scan of the files changed
#                since the previous v* tag (--since overrides; no tag = every tracked file)
#   files        no .env / *.pem / agent.conf tracked
#   pip-audit    pip-audit -r controller/requirements.txt
#   govulncheck  govulncheck ./... in cli/
#   bandit       bandit -q -r controller/app -lll
#   whmcs-text   the WHMCS harness check "no WHMCS in customer-facing strings" (whmcs/tests)
#   hard-constraint  no rum / ISP import in node-selection modules (controller/app/dnsbuild.py, …)
# The manual part (authz, logging of secrets, defaults, downgrade, hard constraint) is the checklist in
# docs/RELEASE.md; the reviewer signs it into release-evidence/vX.Y.Z/security-signoff.md — the template
# is printed at the end.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
since="" template_only=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --since) since="${2:?}"; shift 2 ;;
    --repo) REPO="$(cd "${2:?}" && pwd)"; shift 2 ;;
    --template-only) template_only=1; shift ;;
    *) echo "security-check: unknown argument $1" >&2; exit 2 ;;
  esac
done
TOOL=(python3 "$HERE/release_tool.py" --repo "$REPO")
VERSION="$(head -n1 "$REPO/VERSION" 2>/dev/null || echo 0.0.0)"

template() {
  cat <<TPL
# Security sign-off — Pasargad CDN v$VERSION

Reviewer: <name>            Date (UTC): <YYYY-MM-DD>
Commit:   $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo '<sha>')
Automated check: tools/release/security-check.sh -> exit 0 (output attached)

- [ ] Every new or changed endpoint has the right authorization (admin / capi scope / edge token /
      provisioner token / public) and rate limits where the SPEC asks for them
- [ ] No secret (keys, tokens, passwords, provider API keys, join tokens) is logged, audited, returned
      or put into error texts; new secrets are encrypted at rest
- [ ] New environment variables default to the previous behaviour
- [ ] Migration downgrade tested (upgrade -> downgrade -> upgrade on a copy)
- [ ] Hard constraint (SPEC §23): nothing evades filtering, hides/rotates node IPs or picks nodes by
      reachability; RUM/ISP data never reaches node selection; customers never see node names or IPs
- [ ] Customer-facing texts never mention WHMCS

Notes:

Signed: <name>
TPL
}

if [ "$template_only" = 1 ]; then template; exit 0; fi

fails=0
row() { printf '%-16s %-5s %s\n' "$1" "$2" "$3"; if [ "$2" = FAIL ]; then fails=$((fails + 1)); fi; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ -z "$since" ]; then since="$("${TOOL[@]}" previous-tag 2>/dev/null || true)"; fi
scope="${since:+changes since $since}"; scope="${scope:-all tracked files (no previous tag)}"

# 1. secrets ----------------------------------------------------------------------------------------
if have gitleaks; then
  args=(detect --source "$REPO" --no-banner --redact --exit-code 1)
  if [ -n "$since" ]; then args+=(--log-opts "$since..HEAD"); fi
  if out="$(gitleaks "${args[@]}" 2>&1)"; then row secrets OK "gitleaks: $scope"
  else row secrets FAIL "gitleaks found leaks ($scope)"; printf '%s\n' "$out" | tail -n 30; fi
else
  if out="$("${TOOL[@]}" scan-secrets ${since:+--since "$since"} 2>&1)"; then row secrets OK "built-in scan: $scope"
  else row secrets FAIL "built-in scan ($scope):"; printf '%s\n' "$out" | sed 's/^/    /'; fi
fi

# 2. tracked files ----------------------------------------------------------------------------------
if out="$("${TOOL[@]}" forbidden-files 2>&1)"; then row files OK "no .env / *.pem / agent.conf tracked"
else row files FAIL "forbidden files tracked:"; printf '%s\n' "$out" | sed 's/^/    /'; fi

# 3. dependency audits / static analysis ------------------------------------------------------------
if have pip-audit; then
  if out="$(pip-audit -r "$REPO/controller/requirements.txt" 2>&1)"; then row pip-audit OK "no known vulnerabilities"
  else row pip-audit FAIL "see below"; printf '%s\n' "$out" | tail -n 30; fi
else row pip-audit SKIP "pip-audit not installed (pip install pip-audit)"; fi

if have govulncheck && [ -f "$REPO/cli/go.mod" ]; then
  if out="$(cd "$REPO/cli" && govulncheck ./... 2>&1)"; then row govulncheck OK "cli"
  else row govulncheck FAIL "cli"; printf '%s\n' "$out" | tail -n 30; fi
else row govulncheck SKIP "govulncheck not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)"; fi

if have bandit; then
  if out="$(bandit -q -r "$REPO/controller/app" -lll 2>&1)"; then row bandit OK "no high-severity findings"
  else row bandit FAIL "see below"; printf '%s\n' "$out" | tail -n 30; fi
else row bandit SKIP "bandit not installed (pip install bandit)"; fi

# 4. "no WHMCS in customer-facing strings" — C's harness (whmcs/tests) --------------------------------
wt="$REPO/whmcs/tests"
if [ -x "$wt/run.sh" ]; then
  if out="$("$wt/run.sh" 2>&1)"; then row whmcs-text OK "whmcs/tests/run.sh"
  else row whmcs-text FAIL "whmcs/tests/run.sh"; printf '%s\n' "$out" | tail -n 30; fi
elif [ -d "$wt" ] && ls "$wt"/*.test.js "$wt"/*.test.mjs >/dev/null 2>&1 && have node; then
  if out="$(cd "$REPO" && node --test "$wt"/*.test.*js 2>&1)"; then row whmcs-text OK "node --test whmcs/tests"
  else row whmcs-text FAIL "node --test whmcs/tests"; printf '%s\n' "$out" | tail -n 30; fi
elif [ -d "$wt" ] && ls "$wt"/*[Tt]est*.php >/dev/null 2>&1 && have php; then
  ok=1
  for t in "$wt"/*[Tt]est*.php; do php "$t" >/dev/null 2>&1 || { ok=0; echo "    failed: $t"; }; done
  if [ "$ok" = 1 ]; then row whmcs-text OK "php whmcs/tests"; else row whmcs-text FAIL "php whmcs/tests"; fi
else row whmcs-text SKIP "no WHMCS harness found under whmcs/tests"; fi

# 5. hard constraint --------------------------------------------------------------------------------
if out="$("${TOOL[@]}" hard-constraint 2>&1)"; then row hard-constraint OK "no rum/ISP import in node-selection modules"
else row hard-constraint FAIL "see below"; printf '%s\n' "$out" | sed 's/^/    /'; fi

echo
echo "Manual review: sign the checklist below into release-evidence/v$VERSION/security-signoff.md"
echo "------------------------------------------------------------------------------------------"
template
if [ "$fails" -gt 0 ]; then echo "security-check: $fails check(s) FAILED" >&2; exit 1; fi
exit 0
