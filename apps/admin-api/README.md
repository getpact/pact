# @getpact/admin-api

Workspace administration. Manages users, groups, roles, policies, brains, brain credentials, invites, and JTI revocations. Every mutation is audited fail-closed in the same transaction.

## Endpoints

Under `/v1/workspaces/:id/`:

- `users` (GET, POST)
- `groups` (POST), `groups/:id/members` (POST)
- `policies` (GET, POST) - new POST creates a versioned policy, supersedes previous
- `revocations` (POST) - revoke a JTI, busts revocation KV cache
- `invites` (POST)
- `brains` (GET, POST), `brains/:id` (DELETE), `brains/:id/credential` (PUT)

## Auth

Bearer JWT with `aud=pact-admin` (Mode A). Requires `roles` claim to include `admin`.

## Env

- `DATABASE_URL`, `MEK`, `ISSUER_BASE_URL` (required)
- `ADMIN_AUDIENCE` (default `pact-admin`)
- `REVOCATION_CACHE` - KV namespace for revocation cache bust
- `ENVIRONMENT`
