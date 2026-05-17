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

## Quickstart: pact init

`pact init` creates a workspace on the issuer and stores admin credentials in `~/.pact/credentials`. The issuer requires a Google ID token for `POST /v1/workspaces`, so the CLI runs an OAuth 2.0 PKCE flow (RFC 7636) over a 127.0.0.1 loopback redirect.

```
PACT_GOOGLE_CLIENT_ID=<your-client-id>.apps.googleusercontent.com \
pact init --endpoint https://issuer.getpact.dev \
          --workspace acme \
          --email admin@acme.com
```

The CLI binds a random loopback port, opens `https://accounts.google.com/o/oauth2/v2/auth` in your browser, captures the redirect on `http://127.0.0.1:<port>/callback`, validates the state token, exchanges the auth code with Google directly (public client, no client secret), and posts the resulting `id_token` to the issuer. The admin email must match the verified Google email.

Requirements for the Google OAuth client:

- Type: Web application (loopback addresses are accepted by Google for installed apps).
- Authorized redirect URIs: leave blank (loopback ports are wildcarded by Google).
- Pass the client id via `PACT_GOOGLE_CLIENT_ID` or `--client-id`. `PACT_GOOGLE_CLIENT` is honored as a fallback for users with an existing `pact login` setup; `PACT_GOOGLE_CLIENT_ID` wins when both are set.

For local development against an issuer that sets `PACT_ALLOW_UNAUTHED_WORKSPACE_CREATE=true`, skip the browser step with `--skip-oauth`. The CLI prints a warning and posts the workspace request without a Google token. Do not use `--skip-oauth` against any non-dev issuer; it will fail with `401 unauthorized`.

## Running tests

DB-gated suites (admin, audit, gateway, issuer, mcp, verifier, vault, keystore, db, audit) require a running Postgres with `DATABASE_URL` and `RLS_TEST_DB` set.

```
pnpm test:db           # boots docker postgres, applies migrations, runs all tests
```

To run with an already-running Postgres, copy `.env.example` to `.env`, source it, then `pnpm test`.

Without those env vars, DB-gated suites silently skip (with `describe.skip`). CI enforces they actually run via `scripts/check-db-tests-ran.mjs`.

Run `pnpm verify` before push to catch CI mismatches locally (clears caches, reinstalls from frozen lockfile, runs typecheck and lint). Run `pnpm verify:ci` for the full CI parity check including DB tests (requires docker). Lefthook auto-runs `pnpm test:db` on `git push`; set `PACT_SKIP_PREPUSH_TESTS=1` to skip when iterating fast (CI is still authoritative).

## Operations

`kbjwt_replay_log` grows once per redeem attempt and has no built-in TTL. The `pact-admin-api` Worker runs a daily scheduled trigger (`0 3 * * *` UTC) that calls `prune_kbjwt_replay_log` across every workspace, so a healthy deploy needs no operator action. Set `PACT_REPLAY_RETENTION_DAYS` on the Worker to change the default 7 day window.

For ad-hoc cleanup, the CLI is still available:

```
DATABASE_URL=postgres://... pact admin prune-replay-log --older-than 7d
```

The function runs SECURITY DEFINER and prunes across every workspace in one pass.

Existing workspaces created before the drive HMAC fence or default-audience seeding shipped need a one-shot backfill. The command is idempotent:

```
DATABASE_URL=postgres://... MEK=... pact admin backfill [--workspace <id>] [--what keys|audiences|all] [--dry-run]
```

`--what keys` seeds the missing `adapter-drive` HMAC and `provenance` Ed25519 signing keys. `--what audiences` seeds the missing default audiences. `all` does both.

Recipient send-caps gate `brain.put` writes. Issue, list, and revoke them with the CLI against the admin API:

```
PACT_ADMIN_TOKEN=... PACT_WORKSPACE_ID=... pact send-cap grant --grantee <user-id>
PACT_ADMIN_TOKEN=... PACT_WORKSPACE_ID=... pact send-cap list
PACT_ADMIN_TOKEN=... PACT_WORKSPACE_ID=... pact send-cap revoke <id> --reason "..."
```

## Performance

PRD goal G1: `npx pact init` takes a fresh customer from zero to a working MCP endpoint in under 10 minutes. The init flow boils down to six measurable steps: workspace create, admin bearer issue, first user upsert, MCP audience bearer issue, JWKS fetch, and JWT verify roundtrip.

`apps/issuer/src/__tests__/init-wallclock.test.ts` times every step in process against a local Postgres and asserts the total stays under 5 seconds. The measurement is in-process Hono dispatch (`app.request`) against a local Postgres; it excludes real network, `wrangler dev` boot, the OAuth browser roundtrip, and any DNS or TLS cost. The 5 second budget is a 120x headroom under the PRD G1 ceiling, not a substitute for a real HTTP wall-clock. Cross-app HTTP behavior is covered by `apps/issuer/src/__tests__/composition-e2e.test.ts`. The test is DB-gated and runs as part of `pnpm test:db`. To run it alone:

```
DATABASE_URL=postgres://pact:pact@localhost:5432/pact \
RLS_TEST_DB=postgres://pact_app:pact_app@localhost:5432/pact \
pnpm --filter @getpact/issuer exec vitest run src/__tests__/init-wallclock.test.ts
```

Each run prints a single line of JSON tagged `pact_init_wallclock` with `totalMs`, per-phase `ms`, and the slowest phase. Pipe it through `jq` to track regressions over time.

## Connecting Cursor, Claude Code, and Codex

MCP clients like Cursor, Claude Code, and Codex cannot sign holder-bound KB-JWTs on their own. The `pact mcp bridge` subcommand runs a local HTTP server that holds the holder Ed25519 key, signs a fresh KB-JWT on every forwarded call, and proxies to the remote MCP endpoint.

Run the bridge:

```
PACT_SD_JWT=<sd-jwt compact form> pact mcp bridge --upstream https://mcp.example.com/acme/mcp --port 8765
```

The bridge defaults to `127.0.0.1:8765`. The audience is taken from the SD-JWT `aud` claim unless `--audience` is passed. The holder key is stored at `~/.pact/holder.key` (mode 0600 in a 0700 directory) and is reused across restarts. Delete the file to rotate.

Point each client at the local bridge:

```
{ "mcpServers": { "pact-acme": { "url": "http://localhost:8765/mcp" } } }
```

For Claude Code add the entry to `~/.config/claude-code/config.json` under `mcpServers`. For Cursor and Codex use the same shape in their respective MCP config files.

`--host 0.0.0.0` is supported but not recommended: the bridge signs every forwarded call with the holder key, so anything that can reach the listener can mint presentations until the SD-JWT expires.

The SD-JWT in `PACT_SD_JWT` is readable through `/proc/<pid>/environ` on Linux. For longer-running deployments, prefer a wrapper that reads the token from a file with restricted permissions before exec-ing the bridge.

Other bridge env: `PACT_MCP_PORT` (default 8765), `PACT_MCP_HOST` (default 127.0.0.1), `PACT_AUDIENCE` (override the SD-JWT `aud`).

## Packages

OSS (MIT):

- `@getpact/cli`
- `@getpact/verifier-sdk` (Node.js + edge JWT verifier; exports `verifyPactToken`, `verifyProvenance`, and `JwksCache` for JWKS reuse)
- `@getpact/adapter-sdk`
- `getpact-verifier` (Python, beta; EdDSA JWT verifier)

Internal: `@getpact/core`, `@getpact/db`, `@getpact/crypto`, `@getpact/policy`, `@getpact/audit`, `@getpact/auth`, `@getpact/brain-core`, `@getpact/vault`, `@getpact/keystore`, `@getpact/logger`, `@getpact/ratelimit`, `@getpact/test-helpers`.
