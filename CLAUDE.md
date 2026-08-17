# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Pact: auth for AI agents reading and writing data. A pnpm + turbo monorepo of Cloudflare Workers (`apps/*`) on a shared Postgres, plus shared libraries and published SDKs (`packages/*`). Pre-v1.0.

Requirements: Node 22, pnpm 9, Docker.

## Commands

```bash
pnpm install
docker compose -f infra/compose/docker-compose.yml up -d
pnpm --filter @getpact/db db:migrate
pnpm dev                  # turbo run dev: all workers under wrangler dev

pnpm lint                 # biome check .
pnpm format               # biome format --write .
pnpm typecheck            # turbo, builds deps first
pnpm build

pnpm test                 # turbo run test; DB-gated suites SKIP without env
pnpm test:db              # boots postgres, migrates, runs everything (use this)
pnpm verify               # clean caches + frozen install + typecheck + lint
pnpm verify:ci            # verify + test:db (what pre-push runs)
bash scripts/smoke-demo.sh  # full founder demo over real loopback HTTP
```

### Running one test

DB-gated suites need both env vars or they silently `describe.skip`:

```bash
DATABASE_URL=postgres://pact:pact@localhost:5432/pact \
RLS_TEST_DB=postgres://pact_app:pact_app@localhost:5432/pact \
pnpm --filter @getpact/issuer exec vitest run src/__tests__/issuer.test.ts
```

Or `set -a; . ./.env; set +a` (copy from `.env.example`) then `pnpm test`. `scripts/check-db-tests-ran.mjs` holds the explicit list of DB-gated files and fails CI if any of them skipped - add new DB-gated test files to that list.

App test scripts run `vitest run --no-file-parallelism`; `pnpm test:db` runs turbo at `--concurrency=1`. Tests share one Postgres and take workspace advisory locks, so parallelism is deliberately off.

### Migrations

Drizzle. Edit `packages/db/src/schema.ts`, then `pnpm --filter @getpact/db db:generate` and `db:migrate`. Migrations apply as the `pact` role; runtime connects as `pact_app` (NOBYPASSRLS).

## Architecture

### Workers (`apps/`)

| Worker | Port (local) | Role |
|---|---|---|
| `issuer` | 8787 | workspace create (Google OIDC), token issue/refresh, JWKS, key rotation cron |
| `admin-api` | 8788 | admin mutations (agents, groups, invites, send-caps, audit reads); daily replay-log prune cron |
| `verifier` | 8789 | SD-JWT + KB-JWT verify, revocation, redeem state |
| `mcp-server` | 8790 | MCP tools (`pact.whoami`, `pact.brain.*`, `pact.drive.*`, `pact.audit.recent`) |
| `gateway` | 8791 | Mode B proxy: verify, then forward to an upstream brain with injected credential |
| `web` | 19147 | dashboard BFF; browser only ever sees this origin |

Every worker is a Hono app: `src/index.ts` exports the app (importable in tests), `src/worker.ts` is the Cloudflare entrypoint that adds `scheduled` handlers. Config in `apps/<app>/wrangler.toml`; `[env.local]` holds dev overrides, secrets go in gitignored `.dev.vars`.

### Token model

Two modes bound at issue time, keyed by audience (`packages/core/src/index.ts`):

- **Mode A** (`pact-admin`, `pact-audit`, `pact-mcp`): bearer JWT, workspace Ed25519 signed, audience enforced at issue and verify.
- **Mode B** (`pact-gateway`): SD-JWT with holder binding. `cnf.jwk` binds a holder key; every call carries a fresh KB-JWT (`typ: kb+jwt`) whose `sd_hash` covers the issuer JWS plus selected disclosures. Replay is rejected by the `kbjwt_replay_log` primary key (`kb_replay_detected`, HTTP 410).

Clients that can't sign KB-JWTs use `pact mcp bridge`, a local HTTP MCP server holding `~/.pact/holder.key` that signs each forwarded call.

### Data isolation

All workers share Postgres and connect only as `pact_app`. RLS is keyed on `app.current_workspace_id`, set by `withWorkspace(db, workspaceId, fn)` in `@getpact/db`. Any tenant query goes through that wrapper - a bare `db.select()` on a tenant table will see nothing (or, as `pact`, everything).

### Keys

One deployment MEK wraps every workspace key. Signing keys (`jwt`, `audit`, `provenance`) use AAD `keystore:v1:<workspace>:<kind>`; HMAC keys (`adapter-drive`) use `keystore:hmac:v1:<workspace>:<kind>`. AAD mismatch fails closed. Kinds are deliberately separate so compromise of one doesn't forge the others. Legacy workspaces missing a kind need `pact admin backfill --what keys`.

### Audit

Hash-linked, Ed25519-signed events ordered by `audit_seq` under a per-workspace `pg_advisory_xact_lock`. Admin mutations write audit **in the same transaction** - if audit fails, the mutation rolls back and returns 503. Preserve that coupling when adding admin routes.

### Packages

- `core` - branded ids, `PactError` hierarchy, SSRF/private-host guards, security headers, audience-to-mode map.
- `crypto` - ed25519, jwt, sd-jwt, jcs canonicalization, aes-gcm. `db` - drizzle schema, migrations, `withWorkspace`.
- `keystore` (MEK-wrapped signing/HMAC keys, rotation), `vault` (envelope-encrypted secrets), `auth` (bearer authentication), `policy`, `audit`, `ratelimit`, `logger`, `brain-core` (chunking, search), `adapter-drive`.
- OSS (MIT): `cli` (the `pact` binary), `verifier-sdk-node`, `verifier-sdk-python`, `adapter-sdk`.
- Test-only: `test-helpers` (workspace/token fixtures), `test-harness` (sibling app re-exports).

`SECURITY.md` is the authoritative threat model, with file:line pointers into each mitigation and an explicit list of accepted residual risks. Read the relevant section before changing verification, send-caps, drive attestation, provenance signing, or the audit chain.

### Verifier conformance

`verifier-sdk-node` and `verifier-sdk-python` re-implement the same SD-JWT + KB-JWT checks, so a divergence between them is a security bug. `conformance/verifier-cases.json` is the shared contract; both test suites replay it and must reach the same verdict. Touching either verifier, or the SD-JWT encoder in `@getpact/crypto`, means regenerating it:

```bash
pnpm --filter @getpact/crypto build
node scripts/gen-verifier-fixtures.mjs
```

Generation is deterministic, and CI regenerates and diffs to catch a stale corpus. See `conformance/README.md`, which also records the two known option-surface asymmetries between the SDKs.

## Conventions

- **ASCII only.** A pre-commit hook rejects any non-ASCII byte in tracked text files - smart quotes, em dashes, NBSP, foreign-language comments. Use `-`, `'`, `...`. Legitimate Unicode data needs an entry in `allow_paths` in `lefthook.yml`.
- **ESM everywhere.** `"type": "module"`, relative imports carry `.js` extensions. TS is strict plus `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`.
- **Biome** for lint and format: 2-space, width 100, double quotes, semicolons, trailing commas.
- **No cross-app source imports.** Tests that need a sibling worker's Hono app import it from `@getpact/test-harness`, the one place allowed to reach into `apps/*/src`.
- **New env vars** must be added to `turbo.json` `tasks.test.env` or turbo will not pass them into tests.
- Errors extend `PactError` from `@getpact/core` (code + status), not bare `Error`.

## Hooks and gotchas

- Pre-commit: biome on staged files, full `pnpm typecheck`, ASCII scan, secret-pattern grep. Skip typecheck with `PACT_SKIP_PRECOMMIT_TYPECHECK=1`.
- Pre-push runs `pnpm verify:ci` (slow, needs Docker). Skip with `PACT_SKIP_PREPUSH_TESTS=1`; CI is still authoritative.
- CI (`.github/workflows/ci.yml`): a `build` job (lint, `check:openapi`, typecheck, `test:db`, build, conformance-corpus drift), a `python-sdk` job, and a gitleaks scan.
- `pnpm test` without DB env passes while skipping most real coverage. Use `pnpm test:db` before claiming tests pass.
- `pnpm check:openapi` asserts every `app.<method>("...")` route across the six Workers is documented in `openapi/pact.v1.yaml` with a 2xx and an error response. Adding a route means adding a path entry.
- `pnpm check:cloudflare` is a deploy gate, not a CI gate, and currently fails on purpose: `apps/verifier` and `apps/admin-api` still carry `replace-with-pact-revocation-kv-id`, and `apps/admin-api` carries `replace-with-approved-upstream-hosts`. Real values unblock deploy; wire the check into CI once they land.
- `packages/verifier-sdk-python` has no `package.json`, so pnpm and turbo never see it. Its tests run only in the `python-sdk` CI job. Locally: `pip install "./packages/verifier-sdk-python[test]" && python -m pytest packages/verifier-sdk-python/tests`.
- Packages whose `build` is `tsc --noEmit` (every app, plus `test-harness`) carry a package-level `turbo.json` declaring `"outputs": []`. Without it turbo warns about a missing `dist/**` on every build.
- `scripts/restore-drill.sh` needs `R2_DUMP_KEY`: wrangler still has no R2 object listing command, so the drill cannot discover the newest dump on its own.
