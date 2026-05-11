# Pact quickstart

Five minutes from clone to first audited gateway call.

## Requirements

- Node 22+, pnpm 9+
- Docker (or a reachable Postgres 16 with `DATABASE_URL` + `RLS_TEST_DB` already exported)
- `curl`

## 1. Clone and install

```
git clone https://github.com/getpact/pact && cd pact
pnpm install
```

## 2. Start Postgres and apply migrations

```
docker compose -f infra/compose/docker-compose.yml up -d
pnpm --filter @getpact/db db:migrate
```

The compose file ships dev creds: `pact:pact@localhost:5432/pact`. The migration also creates the lower-privilege `pact_app` role used at runtime.

## 3. Generate a master encryption key

The MEK wraps every workspace signing key and vault secret. Generate one:

```
export MEK=$(openssl rand -base64 32)
export DATABASE_URL=postgres://pact:pact@localhost:5432/pact
export RLS_TEST_DB=postgres://pact_app:pact_app@localhost:5432/pact
export ISSUER_BASE_URL=http://localhost:8787
export PACT_ENDPOINT=$ISSUER_BASE_URL
export ENABLE_DEV_ISSUE=true
export DEV_ISSUE_SECRET=$(openssl rand -base64 32)
```

Keep these in your shell for the rest of the quickstart.

## 4. Run a dev flow without Workers

Pact's HTTP surface is built on Hono, which means the same `app` object can be invoked from a Node script without Wrangler. The repo ships a smoke script that exercises the full flow:

```
pnpm exec node scripts/smoke-cloudflare.mjs
```

For a deployed environment, see `infra/cloudflare/README.md`.

For purely local exploration, run the test suite against your local Postgres:

```
pnpm test:db
```

All 34 turbo tasks should report success and `scripts/check-db-tests-ran.mjs` should print `OK: 11 DB-gated test files ran.`

## 5. Create a workspace by hand

In a second terminal, run the issuer via Wrangler:

```
pnpm --filter @getpact/issuer dev
```

Then:

```
curl -X POST $PACT_ENDPOINT/v1/workspaces \
  -H 'content-type: application/json' \
  -d '{"slug":"acme","name":"Acme","adminEmail":"founder@example.com"}'
```

You receive a `workspaceId`. Issue an admin token:

```
curl -X POST $PACT_ENDPOINT/v1/dev/issue \
  -H 'content-type: application/json' \
  -H "x-pact-dev-issue-secret: $DEV_ISSUE_SECRET" \
  -d '{"workspaceId":"<id>","email":"founder@example.com","audience":"pact-admin"}'
```

The response includes a Pact JWT. Mode A (`pact-admin`) tokens can call admin-api endpoints.

## 6. Register a policy and a brain

Run admin-api:

```
pnpm --filter @getpact/admin-api dev
```

POST a policy that allows admins to invoke any tool and reach the gateway:

```
curl -X POST http://localhost:8788/v1/workspaces/<id>/policies \
  -H "authorization: Bearer <admin-token>" \
  -H 'content-type: application/json' \
  -d '{"body":{"rules":[{"subject":{"kind":"role","value":"admin"},"effect":"allow"}]}}'
```

Register a brain. Use `https://api.example.com` as a stand-in for a real upstream:

```
curl -X POST http://localhost:8788/v1/workspaces/<id>/brains \
  -H "authorization: Bearer <admin-token>" \
  -H 'content-type: application/json' \
  -d '{"kind":"example","baseUrl":"https://api.example.com","authScheme":"none"}'
```

## 7. Make an audited gateway call

Issue a gateway token (Mode B):

```
curl -X POST $PACT_ENDPOINT/v1/dev/issue \
  -H 'content-type: application/json' \
  -H "x-pact-dev-issue-secret: $DEV_ISSUE_SECRET" \
  -d '{"workspaceId":"<id>","email":"founder@example.com","audience":"pact-gateway"}'
```

Run verifier and gateway:

```
pnpm --filter @getpact/verifier dev
pnpm --filter @getpact/gateway dev
```

Call through the gateway:

```
curl http://localhost:8789/<id>/gateway/example/ping \
  -H "authorization: Bearer <gateway-token>"
```

The gateway runs cheap checks, calls the verifier, looks up the brain, forwards to `https://api.example.com/ping`, and writes a `gateway.attempt` and `gateway.get` audit row in the same transaction as the response.

## 8. Read the audit chain

Run audit-api:

```
pnpm --filter @getpact/audit-api dev
```

Issue an audit-audience token, then:

```
curl http://localhost:8790/v1/workspaces/<id>/audit/events \
  -H "authorization: Bearer <audit-token>"
```

Or use the CLI to verify the entire chain end-to-end against the issuer's audit JWKS:

```
pnpm --filter @getpact/cli build
PACT_ENDPOINT=$PACT_ENDPOINT pnpm exec pact audit verify <id>
```

The CLI fetches workspace metadata, walks every event from genesis, recomputes each hash, and validates each Ed25519 signature with the issuer's published public keys.

## Next steps

- Replace `https://api.example.com` with a real brain (Slack, Drive, Notion). See `packages/adapter-slack/` for a worked example and `packages/adapter-sdk/README.md` for the contract.
- Deploy to Cloudflare. See `infra/cloudflare/README.md` and `scripts/deploy-cloudflare.sh`.
- Configure the Zero Trust Gateway egress policy. See [SECURITY.md](../SECURITY.md) section 1.
- For MEK rotation procedure, see [docs/runbook/mek-rotation.md](runbook/mek-rotation.md).

## Troubleshooting

- `pg_isready` not on PATH: `pnpm test:db` falls back to `docker compose exec postgres pg_isready` automatically.
- `too many clients`: lower `PG_POOL_MAX` (default 1 in `test-db.sh`).
- Audit verify reports `chain head mismatch`: clear KV revocation cache or wait 60 seconds for propagation.
- `verifier returned 503` from gateway: ensure `VERIFIER_SERVICE_TOKEN` is set on both verifier and gateway in production. Non-production deploys allow unauthenticated verifier calls (see `SECURITY.md` section 2).
