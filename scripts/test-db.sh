#!/usr/bin/env bash
# Run the full test suite against a local Postgres.
# Boots docker-compose Postgres if not already running, applies migrations,
# then runs vitest with DATABASE_URL/RLS_TEST_DB exported.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE="infra/compose/docker-compose.yml"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"

export DATABASE_URL="${DATABASE_URL:-postgres://pact:pact@${DB_HOST}:${DB_PORT}/pact}"
export RLS_TEST_DB="${RLS_TEST_DB:-postgres://pact_app:pact_app@${DB_HOST}:${DB_PORT}/pact}"
export PG_POOL_MAX="${PG_POOL_MAX:-4}"

if ! docker ps --format '{{.Names}}' | grep -q "compose[-_]postgres"; then
  echo "[test-db] starting local postgres via docker compose"
  docker compose -f "$COMPOSE" up -d
fi

echo "[test-db] waiting for postgres on ${DB_HOST}:${DB_PORT}"
for _ in $(seq 1 30); do
  if pg_isready -h "$DB_HOST" -p "$DB_PORT" -U pact >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "[test-db] applying migrations"
pnpm --filter @getpact/db db:migrate

echo "[test-db] running vitest with concurrency=1"
pnpm exec turbo run test --concurrency=1
