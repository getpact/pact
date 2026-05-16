# pact

Auth for AI agents reading and writing data.

## Status

Pre-v1.0.

## Layout

- `apps/` - Cloudflare Workers (issuer, verifier, mcp-server, gateway, admin-api, web)
- `packages/` - shared libraries and OSS packages
- `infra/cloudflare/` - Wrangler config and Cloudflare resource definitions
- `infra/compose/` - local Postgres + Miniflare

## Local development

Requirements: Node 22, pnpm 9, Docker.

```
pnpm install
docker compose -f infra/compose/docker-compose.yml up -d
pnpm --filter @getpact/db db:migrate
pnpm dev
```

## Running tests

DB-gated suites (admin, audit, gateway, issuer, mcp, verifier, vault, keystore, db, audit) require a running Postgres with `DATABASE_URL` and `RLS_TEST_DB` set.

```
pnpm test:db           # boots docker postgres, applies migrations, runs all tests
```

To run with an already-running Postgres, copy `.env.example` to `.env`, source it, then `pnpm test`.

Without those env vars, DB-gated suites silently skip (with `describe.skip`). CI enforces they actually run via `scripts/check-db-tests-ran.mjs`.

Run `pnpm verify` before push to catch CI mismatches locally (clears caches, reinstalls from frozen lockfile, runs typecheck and lint).

## Packages

OSS (MIT):

- `@getpact/cli`
- `@getpact/verifier-sdk` (Node.js + edge JWT verifier)
- `@getpact/adapter-sdk`
- `getpact-verifier` (Python, beta; EdDSA JWT verifier)

Internal: `@getpact/core`, `@getpact/db`, `@getpact/crypto`, `@getpact/policy`, `@getpact/audit`, `@getpact/vault`, `@getpact/keystore`, `@getpact/logger`, `@getpact/ratelimit`, `@getpact/test-helpers`.
