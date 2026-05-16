# god-mode demo

A three-script demo that shows what changes when an AI agent stops carrying a
full Google OAuth token and starts carrying a Pact-scoped SD-JWT instead.

## The problem

Most AI agents that touch a user's Google Drive today hold a `drive.readonly`
access token. That token can list every file in the account. The agent does
not need every file. It usually needs one folder, sometimes one document. The
token does not know that.

If the agent is prompt-injected, compromised, or just buggy, the blast radius
is the entire account.

## What this demo shows

Three steps against the same fixture of 5000 files across 20 folders.

- `seed.ts` walks the fixture and calls `pact.brain.put` for each file. The
  content is derived deterministically from the file id so the second run
  hashes to the same `content_hash` and the daemon returns
  `idempotent: true` instead of re-ingesting.
- `before.ts` simulates the god-mode path. It loads a mock OAuth token, calls
  a stand-in for the Drive list API, and prints every file it can see. All
  5000.
- `after.ts` mints a Pact capability scoped to one folder, presents that
  capability to `pact.brain.search`, applies the scope filter, and prints
  only the files inside that folder. 12.

Both paths use the same underlying data, so the diff is the whole point.

## Run it (end-to-end against a local stack)

Bring up Postgres and run migrations:

```
docker compose up -d
pnpm --filter @getpact/db db:migrate
pnpm dev
```

`pnpm dev` runs the issuer (port 8787), verifier (port 8789),
admin-api (port 8788), and mcp-server (port 8790) under wrangler.

Export the local endpoints and credentials, then seed and run:

```
export PACT_API_BASE=http://127.0.0.1:8787
export PACT_ADMIN_TOKEN=...           # admin bearer for issuer admin routes
export PACT_AGENT_ID=...              # provisioned agent uuid (see admin-api)
export PACT_ON_BEHALF_OF=alice@example.com
export PACT_MCP_URL=http://127.0.0.1:8790/<workspace>/mcp
export PACT_MCP_TOKEN=...             # user bearer with mcp audience
export PACT_DEMO_QUERY="Q3 planning notes"

pnpm --filter @getpact/example-god-mode demo:seed
pnpm --filter @getpact/example-god-mode demo:before
pnpm --filter @getpact/example-god-mode demo:after
```

Or step through them from this directory:

```
pnpm demo:seed
pnpm demo:before
pnpm demo:after
```

`run.sh` runs `before` and `after` and prints the file-count diff at the end.

## What is real and what is stubbed

Real when the stack is up and the env vars above are set:

- `seed.ts` posts a JSON-RPC `tools/call` for `pact.brain.put` per file to
  the mcp-server. The brain layer chunks, embeds, and stores each page. A
  second run is a no-op because the page row is keyed on
  `(source_uri, content_hash)`.
- `after.ts` mints a capability through the issuer admin route
  `POST /v1/agents/:agentId/capabilities`. The returned SD-JWT is what the
  agent would carry across the wire.
- `after.ts` then posts a JSON-RPC `tools/call` for `pact.brain.search`
  against the mcp-server and applies the SD-JWT's `scope.folder_id` to the
  returned chunk source URIs.

Falls back to a self-contained stub when the stack is not configured:

- If `PACT_API_BASE` or `PACT_ADMIN_TOKEN` is unset, `mintCapability`
  returns a structurally sd-jwt-shaped token whose signature is a
  placeholder. The rest of the script does not change shape.
- If `PACT_MCP_URL` or `PACT_MCP_TOKEN` is unset, `searchBrain` filters
  the fixture client-side against the capability's
  `scope.folder_id`, so the output still shows the 5000 -> 12 reduction.
- `seed.ts` without those vars prints a dry-run summary of what it would
  POST.

The fallback path is what makes the demo runnable from a clean checkout in
under a minute. The live path is what proves the wiring works end to end.

## Open limits in v0.1

- The brain layer enforces workspace isolation. It does not yet enforce
  per-folder scope. The demo applies the `scope.folder_id` filter on the
  client. The same filter belongs server-side in `pact.brain.search`; that
  is tracked separately.
- The capability is minted with `cnf_jwk` omitted, so the SD-JWT is not
  bound to a holder key in this demo. A KB-JWT presentation requires the
  recipient (agent) private key, which is not exposed by the daemon CLI
  yet. Production presentation will add a KB-JWT once agent keys are
  managed.

## Recording

Operators are welcome to record their own walkthrough (Loom, asciinema,
etc.). No artifact is committed to the repo.

## Files

- `seed.ts` - ingests the fixture into the brain via `pact.brain.put`
- `before.ts` - god-mode path
- `after.ts` - scoped path
- `drive-fixture.json` - 5000 files, 20 folders, 12 in `folder_X`
- `run.sh` - one-shot runner that prints before, after, and the diff
- `__tests__/demo.test.ts` - call-shape and diff-math tests
- `package.json` - scripts (`demo:seed`, `demo:before`, `demo:after`, `demo:run`, `test`, `typecheck`)
