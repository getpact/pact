# Local test loop

Use the smallest loop that covers the code you changed, then widen before commit.

## Fast loops

Run all non-DB tests:

```
pnpm test
```

Run one package or app:

```
pnpm --filter @getpact/policy test
pnpm --filter @getpact/verifier test
pnpm --filter @getpact/gateway test
```

Run type checks:

```
pnpm typecheck
```

Run Biome:

```
pnpm lint
```

## DB-backed loop

Run the DB-backed suite with local Docker Postgres:

```
pnpm test:db
```

`scripts/test-db.sh` starts `infra/compose/docker-compose.yml` when `DATABASE_URL` and
`RLS_TEST_DB` are not already set, applies migrations, runs Vitest with concurrency 1, and then
checks that DB-gated test files did not silently skip.

To use an external Postgres, export both URLs before running:

```
export DATABASE_URL=postgres://pact:pact@localhost:5432/pact
export RLS_TEST_DB=postgres://pact_app:pact_app@localhost:5432/pact
pnpm test:db
```

`DATABASE_URL` is for migrations and setup. `RLS_TEST_DB` is the lower-privilege runtime role used
to exercise row-level security.

## Failure signals

- Missing `DATABASE_URL` or `RLS_TEST_DB`: set both or neither.
- DB-gated test file reported skipped: the suite did not exercise the real database path.
- `too many clients`: lower `PG_POOL_MAX`, or use the default from `scripts/test-db.sh`.
- Slow or flaky DB run: confirm no other local process is exhausting Postgres connections.
