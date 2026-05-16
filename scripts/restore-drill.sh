#!/usr/bin/env bash
# Restore drill. Pulls the most recent Postgres dump from R2, replays it into an
# ephemeral Docker Postgres, applies pending migrations, and runs smoke checks
# against the restored instance. Intended for the weekly GitHub Actions cron and
# for ad hoc verification from an operator workstation.
#
# Required env:
#   R2_BUCKET                  R2 bucket holding nightly dumps (default pact-backups)
#   R2_DUMP_PREFIX             Object prefix for Postgres dumps (default postgres/)
#   CLOUDFLARE_ACCOUNT_ID      Cloudflare account that owns the bucket
#   CLOUDFLARE_API_TOKEN       Token with R2 read access
#   PACT_DRILL_WORKSPACE_ID    Workspace id used for the audit chain smoke check
#
# Optional env:
#   DRILL_PG_IMAGE             Postgres image to run (default postgres:16)
#   DRILL_PG_PORT              Host port to bind (default 55433)
#   DRILL_KEEP_CONTAINER       1 to leave the container running after exit
#
# Exit codes:
#   0  drill succeeded
#   1  preflight failed (missing tools or env)
#   2  failed to fetch dump from R2
#   3  failed to restore dump into Postgres
#   4  migration check failed (dump older than current schema)
#   5  smoke query failed (missing key tables or empty workspace)
#   6  audit chain verification failed

set -euo pipefail

R2_BUCKET="${R2_BUCKET:-pact-backups}"
R2_DUMP_PREFIX="${R2_DUMP_PREFIX:-postgres/}"
DRILL_PG_IMAGE="${DRILL_PG_IMAGE:-postgres:16}"
DRILL_PG_PORT="${DRILL_PG_PORT:-55433}"
DRILL_KEEP_CONTAINER="${DRILL_KEEP_CONTAINER:-0}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONTAINER="pact-restore-drill-$$"
WORK="$(mktemp -d)"
DUMP_LOCAL="$WORK/pact.sql.gz"
DUMP_PLAIN="$WORK/pact.sql"

structured_error() {
  local code="$1"
  local stage="$2"
  local detail="$3"
  printf '{"status":"error","code":%s,"stage":"%s","detail":"%s"}\n' \
    "$code" "$stage" "$detail" >&2
}

cleanup() {
  if [ "$DRILL_KEEP_CONTAINER" != "1" ]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    structured_error 1 preflight "missing command: $1"
    exit 1
  fi
}

require_cmd docker
require_cmd psql
require_cmd gunzip
require_cmd wrangler
require_cmd pnpm

for var in CLOUDFLARE_ACCOUNT_ID CLOUDFLARE_API_TOKEN PACT_DRILL_WORKSPACE_ID; do
  if [ -z "${!var:-}" ]; then
    structured_error 1 preflight "missing env: $var"
    exit 1
  fi
done

echo "[drill] starting ephemeral postgres ($DRILL_PG_IMAGE on $DRILL_PG_PORT)"
docker run -d --name "$CONTAINER" \
  -e POSTGRES_USER=pact \
  -e POSTGRES_PASSWORD=pact \
  -e POSTGRES_DB=pact \
  -p "$DRILL_PG_PORT:5432" \
  "$DRILL_PG_IMAGE" >/dev/null

ready=false
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -U pact >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [ "$ready" != "true" ]; then
  structured_error 3 boot "postgres failed to become ready within 60s"
  exit 3
fi

export RESTORE_DATABASE_URL="postgres://pact:pact@127.0.0.1:${DRILL_PG_PORT}/pact"

echo "[drill] locating most recent dump under r2://${R2_BUCKET}/${R2_DUMP_PREFIX}"
listing="$(wrangler r2 object get "$R2_BUCKET" --prefix "$R2_DUMP_PREFIX" --list 2>/dev/null || true)"
if [ -z "$listing" ]; then
  structured_error 2 r2_list "no objects found under ${R2_DUMP_PREFIX}"
  exit 2
fi
key="$(printf '%s\n' "$listing" | awk '{print $1}' | sort | tail -n 1)"
if [ -z "$key" ]; then
  structured_error 2 r2_list "could not parse key from listing"
  exit 2
fi

echo "[drill] fetching $key"
if ! wrangler r2 object get "${R2_BUCKET}/${key}" --file "$DUMP_LOCAL" >/dev/null 2>&1; then
  structured_error 2 r2_get "wrangler r2 get failed for $key"
  exit 2
fi

echo "[drill] decompressing"
if ! gunzip -c "$DUMP_LOCAL" > "$DUMP_PLAIN"; then
  structured_error 3 decompress "gunzip failed"
  exit 3
fi

echo "[drill] restoring into ephemeral postgres"
if ! psql "$RESTORE_DATABASE_URL" -v ON_ERROR_STOP=1 -q < "$DUMP_PLAIN"; then
  structured_error 3 restore "psql restore failed"
  exit 3
fi

echo "[drill] applying pending migrations (expect zero on a current dump)"
migrate_log="$WORK/migrate.log"
if ! DATABASE_URL="$RESTORE_DATABASE_URL" \
     pnpm --filter @getpact/db db:migrate > "$migrate_log" 2>&1; then
  structured_error 4 migrate "db:migrate failed; see $migrate_log"
  exit 4
fi
applied_after="$(grep -c -i "applying" "$migrate_log" || true)"
if [ "${applied_after:-0}" -gt 0 ]; then
  echo "[drill] warning: dump trailed deployed schema by ${applied_after} migration(s)"
fi

echo "[drill] smoke: row counts on key tables"
counts="$(psql "$RESTORE_DATABASE_URL" -tAc \
  "SELECT t || '=' || c FROM (
     SELECT 'workspaces' AS t, count(*) AS c FROM workspaces UNION ALL
     SELECT 'users', count(*) FROM users UNION ALL
     SELECT 'signing_keys', count(*) FROM signing_keys UNION ALL
     SELECT 'audit_events', count(*) FROM audit_events
   ) s;" 2>/dev/null || true)"
if [ -z "$counts" ]; then
  structured_error 5 smoke_counts "one or more key tables missing"
  exit 5
fi
echo "[drill] counts: $(echo "$counts" | tr '\n' ' ')"

ws_present="$(psql "$RESTORE_DATABASE_URL" -tAc \
  "SELECT count(*) FROM workspaces WHERE id = '${PACT_DRILL_WORKSPACE_ID}';" 2>/dev/null || echo 0)"
if [ "$ws_present" != "1" ]; then
  structured_error 5 smoke_workspace "drill workspace ${PACT_DRILL_WORKSPACE_ID} not present in dump"
  exit 5
fi

echo "[drill] verifying audit chain for workspace ${PACT_DRILL_WORKSPACE_ID}"
verify_log="$WORK/audit-verify.log"
if ! DATABASE_URL="$RESTORE_DATABASE_URL" \
     PACT_WORKSPACE_ID="$PACT_DRILL_WORKSPACE_ID" \
     pnpm --filter @getpact/cli exec pact audit verify > "$verify_log" 2>&1; then
  structured_error 6 audit_verify "pact audit verify failed; tail: $(tail -n 3 "$verify_log" | tr '\n' ' ')"
  exit 6
fi
if ! grep -q "chain ok" "$verify_log"; then
  structured_error 6 audit_verify "audit verify did not report chain ok"
  exit 6
fi

echo "[drill] ok"
exit 0
