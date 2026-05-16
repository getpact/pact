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

## Operations

`kbjwt_replay_log` grows once per redeem attempt and has no built-in TTL. Prune it on a schedule (weekly is fine) once you outlive your longest capability:

```
DATABASE_URL=postgres://... pact admin prune-replay-log --older-than 7d
```

The function runs SECURITY DEFINER and prunes across every workspace in one pass. Wire it into cron, a Worker scheduled trigger, or your migration runner.

Existing workspaces created before the drive HMAC fence or default-audience seeding shipped need a one-shot backfill. The command is idempotent:

```
DATABASE_URL=postgres://... MEK=... pact admin backfill [--workspace <id>] [--what keys|audiences|all] [--dry-run]
```

`--what keys` seeds the missing `adapter-drive` HMAC key. `--what audiences` seeds the missing default audiences. `all` does both.

## Packages

OSS (MIT):

- `@getpact/cli`
- `@getpact/verifier-sdk` (Node.js + edge JWT verifier)
- `@getpact/adapter-sdk`
- `getpact-verifier` (Python, beta; EdDSA JWT verifier)

Internal: `@getpact/core`, `@getpact/db`, `@getpact/crypto`, `@getpact/policy`, `@getpact/audit`, `@getpact/vault`, `@getpact/keystore`, `@getpact/logger`, `@getpact/ratelimit`, `@getpact/test-helpers`.
