#!/usr/bin/env bash
# Run the full test suite against Postgres.
# If DATABASE_URL and RLS_TEST_DB are already set, use them as-is. Otherwise
# boot docker-compose Postgres, apply migrations, then run vitest.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE="infra/compose/docker-compose.yml"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
EXTERNAL_DB=false

if [ -n "${DATABASE_URL:-}" ] && [ -z "${RLS_TEST_DB:-}" ]; then
  echo "[test-db] RLS_TEST_DB is required when DATABASE_URL is provided" >&2
  exit 1
fi

if [ -z "${DATABASE_URL:-}" ] && [ -n "${RLS_TEST_DB:-}" ]; then
  echo "[test-db] DATABASE_URL is required when RLS_TEST_DB is provided" >&2
  exit 1
fi

if [ -n "${DATABASE_URL:-}" ] && [ -n "${RLS_TEST_DB:-}" ]; then
  EXTERNAL_DB=true
fi

export DATABASE_URL="${DATABASE_URL:-postgres://pact:pact@${DB_HOST}:${DB_PORT}/pact}"
export RLS_TEST_DB="${RLS_TEST_DB:-postgres://pact_app:pact_app@${DB_HOST}:${DB_PORT}/pact}"
export PG_POOL_MAX="${PG_POOL_MAX:-1}"
export PG_IDLE_TIMEOUT="${PG_IDLE_TIMEOUT:-1}"
export PACT_REQUIRE_DB=1

if [ "$EXTERNAL_DB" = "false" ]; then
  if ! docker info >/dev/null 2>&1; then
    echo "[test-db] docker daemon is unavailable; start Docker or provide DATABASE_URL/RLS_TEST_DB" >&2
    exit 1
  fi

  if ! docker ps --format '{{.Names}}' | grep -q "compose[-_]postgres"; then
    echo "[test-db] starting local postgres via docker compose"
    docker compose -f "$COMPOSE" up -d
  fi

  echo "[test-db] waiting for postgres on ${DB_HOST}:${DB_PORT}"
  ready=false
  for _ in $(seq 1 30); do
    if command -v pg_isready >/dev/null 2>&1; then
      pg_isready -h "$DB_HOST" -p "$DB_PORT" -U pact >/dev/null 2>&1 && ready=true
    else
      docker compose -f "$COMPOSE" exec -T postgres pg_isready -U pact >/dev/null 2>&1 && ready=true
    fi
    if [ "$ready" = "true" ]; then
      break
    fi
    sleep 1
  done
  if [ "$ready" != "true" ]; then
    echo "[test-db] postgres was not ready on ${DB_HOST}:${DB_PORT} after 30s" >&2
    exit 1
  fi
else
  echo "[test-db] using externally provided DATABASE_URL and RLS_TEST_DB"
fi

echo "[test-db] refreshing collation version (silences glibc-skew warning)"
if command -v psql >/dev/null 2>&1; then
  PGPASSWORD=pact psql -h "$DB_HOST" -p "$DB_PORT" -U pact -d pact -v ON_ERROR_STOP=1 -c "ALTER DATABASE pact REFRESH COLLATION VERSION;" >/dev/null 2>&1 || true
else
  docker compose -f "$COMPOSE" exec -T postgres psql -U pact -d pact -v ON_ERROR_STOP=1 -c "ALTER DATABASE pact REFRESH COLLATION VERSION;" >/dev/null 2>&1 || true
fi

echo "[test-db] applying migrations"
pnpm --filter @getpact/db db:migrate

echo "[test-db] running vitest with concurrency=1"
LOG="${PACT_DB_TEST_LOG:-/tmp/pact-db-tests.log}"
pnpm exec turbo run test --force --concurrency=1 2>&1 | tee "$LOG"

echo "[test-db] checking DB-gated tests were not skipped"
node scripts/check-db-tests-ran.mjs "$LOG"
