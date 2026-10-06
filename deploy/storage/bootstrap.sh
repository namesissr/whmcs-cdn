#!/bin/sh
# Write the storage server's identities (SPEC §16.8, docs/STORAGE.md) and print the controller's
# credentials ONCE.  Run on the storage server, next to .env:   ./bootstrap.sh  [--rotate]
#
# It creates s3.json with exactly two operator identities:
#   * pcdn-admin       — break-glass Admin (bootstrap, upgrades, recovery). Stays on this server.
#   * pcdn-controller  — what the controller uses: s3:* on the cdn-* buckets plus the IAM calls that
#                        create and delete a customer's access key. No Admin, no other bucket, no
#                        access to the server's own configuration.
# and an `anonymous` identity with no permissions, which is what lets a bucket policy allow the
# edges' Referer-conditioned GET of a bucket used as a CDN origin (and nothing else).
#
# Customer keys are NOT written here: the controller creates them over the IAM API and the server
# keeps them in the filer, so they survive restarts and never sit in a file.
#
# --rotate gives the controller a new secret (update the controller's .env and restart it).
set -eu
cd "$(dirname "$0")"
COMPOSE="docker compose"
ROTATE=0
while [ $# -gt 0 ]; do
  case "$1" in
    -f) COMPOSE="$COMPOSE -f $2"; shift 2 ;;
    --rotate) ROTATE=1; shift ;;
    *) echo "usage: $0 [-f compose-file] [--rotate]" >&2; exit 2 ;;
  esac
done
[ -f .env ] || { echo ".env missing: cp .env.example .env and edit it" >&2; exit 1; }

# Docker creates a DIRECTORY for a bind-mount source that does not exist yet, so a `docker compose
# up -d` run before the first bootstrap leaves an empty s3.json/ behind — and the gateway then dies
# with "fail to load config file ... is a directory" (Caddy answers 502). Clean that up here.
if [ -d s3.json ]; then
  rmdir s3.json 2>/dev/null || {
    echo "s3.json is a directory and not empty; move it aside and run this again" >&2; exit 1; }
  echo "removed the empty s3.json directory Docker had created for the bind mount"
fi

rand() { head -c 96 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-"$1"; }
value_of() { sed -n "s/^$1=//p" .env | tail -1; }

CTRL_KEY=$(value_of PCDN_CONTROLLER_KEY)
ADMIN_KEY=$(value_of PCDN_ADMIN_KEY)
PREFIX=$(value_of STORAGE_BUCKET_PREFIX); PREFIX=${PREFIX:-cdn-}

if [ -f s3.json ] && [ "$ROTATE" = 0 ]; then
  echo "s3.json exists; keeping the identities in it (use --rotate for a new controller secret)."
  echo "The controller's access key is in s3.json on this server if you need to read it again."
  exit 0
fi

# Keep the admin identity across a --rotate: only the controller's secret changes.
if [ -f s3.json ]; then
  ADMIN_KEY=$(sed -n 's/.*"accessKey": "\([A-Za-z0-9]*\)".*/\1/p' s3.json | head -1)
  ADMIN_SECRET=$(sed -n 's/.*"secretKey": "\([A-Za-z0-9]*\)".*/\1/p' s3.json | head -1)
fi
ADMIN_KEY=${ADMIN_KEY:-$(rand 20)}
ADMIN_SECRET=${ADMIN_SECRET:-$(rand 48)}
CTRL_KEY=${CTRL_KEY:-$(rand 20)}
CTRL_SECRET=$(rand 48)

umask 077
cat > s3.json <<JSON
{
  "identities": [
    {
      "name": "pcdn-admin",
      "credentials": [{"accessKey": "$ADMIN_KEY", "secretKey": "$ADMIN_SECRET"}],
      "actions": ["Admin"]
    },
    {
      "name": "pcdn-controller",
      "credentials": [{"accessKey": "$CTRL_KEY", "secretKey": "$CTRL_SECRET"}],
      "policyNames": ["pcdn-controller"]
    },
    {
      "name": "anonymous",
      "actions": []
    }
  ],
  "policies": [
    {
      "name": "pcdn-controller",
      "content": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"PcdnCustomerBucketsOnly\",\"Effect\":\"Allow\",\"Action\":[\"s3:*\"],\"Resource\":[\"arn:aws:s3:::${PREFIX}*\",\"arn:aws:s3:::${PREFIX}*/*\"]},{\"Sid\":\"PcdnCustomerKeys\",\"Effect\":\"Allow\",\"Action\":[\"iam:CreateUser\",\"iam:DeleteUser\",\"iam:GetUser\",\"iam:PutUserPolicy\",\"iam:DeleteUserPolicy\",\"iam:GetUserPolicy\",\"iam:CreateAccessKey\",\"iam:DeleteAccessKey\",\"iam:ListAccessKeys\"],\"Resource\":[\"*\"]}]}"
    }
  ]
}
JSON
chmod 600 s3.json

$COMPOSE up -d
# The static identities are read at startup, so the gateway has to see the new file. Recreate rather
# than restart: when the bind-mount source has just changed (a file where a directory was), a
# restarted container keeps the old mount.
$COMPOSE up -d --force-recreate seaweedfs >/dev/null
echo
echo "Put these into the CONTROLLER's .env (not this server's), then restart the controller:"
echo "  STORAGE_BACKEND=seaweedfs"
echo "  STORAGE_ADMIN_ACCESS_KEY=$CTRL_KEY"
echo "  STORAGE_ADMIN_SECRET_KEY=$CTRL_SECRET"
echo
echo "The break-glass admin identity (pcdn-admin) stays in s3.json on this server."
