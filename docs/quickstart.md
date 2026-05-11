# Pact quickstart

Five minutes from clone to first audited gateway call.

## Requirements

- Node 22+, pnpm 9.15+
- Docker, or a reachable Postgres 16 with `DATABASE_URL` and `RLS_TEST_DB` exported
- `curl`, `jq`, and `openssl`

## 1. Clone and install

```
git clone https://github.com/getpact/pact && cd pact
pnpm install
```

## 2. Configure local env and migrate

```
export DATABASE_URL=${DATABASE_URL:-postgres://pact:pact@localhost:5432/pact}
export RLS_TEST_DB=${RLS_TEST_DB:-postgres://pact_app:pact_app@localhost:5432/pact}
export MEK=$(openssl rand -base64 32)
export DEV_ISSUE_SECRET=$(openssl rand -base64 32)
export ISSUER_BASE_URL=http://localhost:8787
```

`DATABASE_URL` is the migration/admin role. Runtime Workers must use the lower-privilege
`RLS_TEST_DB` role so row-level security is enforced. Wrangler reads Worker bindings from each
app's `.dev.vars`, so write local-only files:

```
cat > apps/issuer/.dev.vars <<EOF
DATABASE_URL=$RLS_TEST_DB
MEK=$MEK
ISSUER_BASE_URL=$ISSUER_BASE_URL
ENVIRONMENT=development
ENABLE_DEV_ISSUE=true
DEV_ISSUE_SECRET=$DEV_ISSUE_SECRET
EOF

cat > apps/admin-api/.dev.vars <<EOF
DATABASE_URL=$RLS_TEST_DB
MEK=$MEK
ISSUER_BASE_URL=$ISSUER_BASE_URL
ENVIRONMENT=development
ADMIN_AUDIENCE=pact-admin
UPSTREAM_HOST_ALLOWLIST=httpbin.org
EOF

cat > apps/verifier/.dev.vars <<EOF
DATABASE_URL=$RLS_TEST_DB
MEK=$MEK
ISSUER_BASE_URL=$ISSUER_BASE_URL
ENVIRONMENT=development
VERIFIER_AUDIENCES=pact-mcp,pact-gateway
EOF

cat > apps/gateway/.dev.vars <<EOF
DATABASE_URL=$RLS_TEST_DB
MEK=$MEK
ENVIRONMENT=development
GATEWAY_AUDIENCE=pact-gateway
GATEWAY_AUDIT_MODE=required
UPSTREAM_HOST_ALLOWLIST=httpbin.org
VERIFIER_URL=http://localhost:8789
EOF

cat > apps/audit-api/.dev.vars <<EOF
DATABASE_URL=$RLS_TEST_DB
ISSUER_BASE_URL=$ISSUER_BASE_URL
ENVIRONMENT=development
AUDIT_AUDIENCE=pact-audit
EOF

node scripts/check-quickstart-local.mjs
```

Start Postgres and apply migrations. If `DATABASE_URL` and `RLS_TEST_DB` point to an external
Postgres, skip the first two Docker lines and run the migration command only.

```
docker compose -f infra/compose/docker-compose.yml up -d
until docker compose -f infra/compose/docker-compose.yml exec -T postgres pg_isready -U pact >/dev/null 2>&1; do sleep 1; done
pnpm --filter @getpact/db db:migrate
```

The compose file ships dev creds: `pact:pact@localhost:5432/pact`. The migration also creates
the lower-privilege `pact_app` login used by runtime Workers and DB-backed tests.

## 3. Start the local Workers

Run each command in its own terminal from the repo root. For a service map, see
[docs/dev-onboarding/workers-and-ports.md](dev-onboarding/workers-and-ports.md).

```
pnpm --dir apps/issuer exec wrangler dev --port 8787
pnpm --dir apps/admin-api exec wrangler dev --port 8788
pnpm --dir apps/verifier exec wrangler dev --port 8789
pnpm --dir apps/gateway exec wrangler dev --port 8790
pnpm --dir apps/audit-api exec wrangler dev --port 8791
```

## 4. Create a workspace

In another shell, keep the same exports from step 2 and create a workspace:

```
export WORKSPACE_ID=$(
  curl -fsS -X POST http://localhost:8787/v1/workspaces \
    -H 'content-type: application/json' \
    -d '{"slug":"acme","name":"Acme","adminEmail":"founder@example.com"}' \
  | jq -r .workspaceId
)
```

Issue an admin token:

```
export ADMIN_TOKEN=$(
  curl -fsS -X POST http://localhost:8787/v1/dev/issue \
    -H 'content-type: application/json' \
    -H "x-pact-dev-issue-secret: $DEV_ISSUE_SECRET" \
    -d "{\"workspaceId\":\"$WORKSPACE_ID\",\"email\":\"founder@example.com\",\"audience\":\"pact-admin\"}" \
  | jq -r .token
)
```

Mode A (`pact-admin`) tokens can call admin-api endpoints.

## 5. Register a policy and a brain

POST a narrow policy that allows admins to make this one gateway call:

```
curl -fsS -X POST "http://localhost:8788/v1/workspaces/$WORKSPACE_ID/policies" \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"body":{"rules":[{"subject":{"kind":"role","value":"admin"},"effect":"allow","action":"gateway.get","resource":"gateway:httpbin:/get"}]}}' \
  | jq
```

Register an `httpbin` brain:

```
curl -fsS -X POST "http://localhost:8788/v1/workspaces/$WORKSPACE_ID/brains" \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"kind":"httpbin","baseUrl":"https://httpbin.org","authScheme":"none"}' \
  | jq
```

## 6. Make an audited gateway call

Issue a gateway token (Mode B):

```
export GATEWAY_TOKEN=$(
  curl -fsS -X POST http://localhost:8787/v1/dev/issue \
    -H 'content-type: application/json' \
    -H "x-pact-dev-issue-secret: $DEV_ISSUE_SECRET" \
    -d "{\"workspaceId\":\"$WORKSPACE_ID\",\"email\":\"founder@example.com\",\"audience\":\"pact-gateway\"}" \
  | jq -r .token
)
```

Call through the gateway:

```
curl -fsS http://localhost:8790/acme/gateway/httpbin/get \
  -H "authorization: Bearer $GATEWAY_TOKEN" \
  | jq
```

The gateway checks the token, calls the verifier, looks up the brain, forwards to
`https://httpbin.org/get`, and writes signed gateway audit rows. With
`GATEWAY_AUDIT_MODE=required`, it fails closed if a required audit row cannot be written.

## 7. Read the audit chain

Issue an audit token:

```
export AUDIT_TOKEN=$(
  curl -fsS -X POST http://localhost:8787/v1/dev/issue \
    -H 'content-type: application/json' \
    -H "x-pact-dev-issue-secret: $DEV_ISSUE_SECRET" \
    -d "{\"workspaceId\":\"$WORKSPACE_ID\",\"email\":\"founder@example.com\",\"audience\":\"pact-audit\"}" \
  | jq -r .token
)
```

Read the gateway audit event:

```
curl -fsS "http://localhost:8791/v1/workspaces/$WORKSPACE_ID/audit/events?action=gateway.get&limit=5" \
  -H "authorization: Bearer $AUDIT_TOKEN" \
  | jq '.events[] | {action, decision, target}'
```

You should see at least one `gateway.get` event with `decision` set to `allow`.

## 8. Optional checks

Run the DB-backed suite against the same local Postgres:

```
pnpm test:db
```

Check the local Worker health endpoints:

```
node scripts/check-quickstart-local.mjs --health
```

For deployed environments, see `infra/cloudflare/README.md`.

## Next steps

- Replace `https://httpbin.org` with a real brain (Slack, Drive, Notion). See `packages/adapter-slack/` for a worked example and `packages/adapter-sdk/README.md` for the contract.
- Deploy to Cloudflare. See `infra/cloudflare/README.md` and `scripts/deploy-cloudflare.sh`.
- Configure the Zero Trust Gateway egress policy. See [SECURITY.md](../SECURITY.md) section 1.
- For MEK rotation procedure, see [docs/runbook/mek-rotation.md](runbook/mek-rotation.md).

## Troubleshooting

- `dev issue` returns `404`: check `ENABLE_DEV_ISSUE=true`, `ENVIRONMENT=development`, and `DEV_ISSUE_SECRET` in `apps/issuer/.dev.vars`, then restart issuer.
- `address already in use`: make sure each Worker uses the explicit port shown above.
- `unsafe runtime database role`: make sure every app `.dev.vars` uses `DATABASE_URL=$RLS_TEST_DB`, not the migration/admin `DATABASE_URL`.
- `pg_isready` not on PATH: `pnpm test:db` falls back to `docker compose -f infra/compose/docker-compose.yml exec -T postgres pg_isready -U pact`.
- `too many clients`: lower `PG_POOL_MAX` (default 1 in `test-db.sh`).
- `gateway` returns `denied`: confirm the policy was created and verifier has `VERIFIER_AUDIENCES=pact-mcp,pact-gateway`.
- `gateway` returns `brain not found`: confirm the brain kind in the URL matches the registered kind, `httpbin`.
- `verifier returned 503` from gateway: ensure `VERIFIER_SERVICE_TOKEN` is set on both verifier and gateway in production. Non-production deploys allow unauthenticated verifier calls (see `SECURITY.md` section 2).
