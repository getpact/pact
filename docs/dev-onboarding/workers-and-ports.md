# Local Workers and ports

This is the local service map used by `docs/quickstart.md`.

## Ports

Run each Worker in its own terminal:

| App | Package | Local URL | Purpose |
| --- | --- | --- | --- |
| issuer | `@getpact/issuer` | `http://localhost:8787` | Creates workspaces and issues tokens. |
| admin-api | `@getpact/admin-api` | `http://localhost:8788` | Manages users, policies, revocations, invites, and brains. |
| verifier | `@getpact/verifier` | `http://localhost:8789` | Verifies token, action, resource, and policy decisions. |
| gateway | `@getpact/gateway` | `http://localhost:8790` | Proxies approved Mode B calls to registered brains. |
| audit-api | `@getpact/audit-api` | `http://localhost:8791` | Reads audit events, workspace audit metadata, and chain state. |

## Calls

- `gateway` calls `verifier` through `VERIFIER_URL`.
- `admin-api`, `audit-api`, `gateway`, `issuer`, and `verifier` all connect to Postgres.
- Runtime Workers should connect with the lower-privilege `pact_app` role, not the migration role.
- `admin-api` and `gateway` both enforce `UPSTREAM_HOST_ALLOWLIST` for brain upstreams.

## Quick checks

Before starting Workers:

```
node scripts/check-quickstart-local.mjs
```

After starting Workers:

```
node scripts/check-quickstart-local.mjs --health
```
