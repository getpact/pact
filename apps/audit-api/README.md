# @getpact/audit-api

Read-only audit log access. Cursor-paginated, ordered by `audit_seq`. Audit events are hash-linked and signed; consumers can verify chain integrity using audit JWKS from the issuer.

## Endpoints

- `GET /v1/workspaces/:id/audit/events` - list events; filters: `action`, `since`, `until`, `limit`, `cursor`, `order`
- `GET /v1/workspaces/:id/audit/workspace` - workspace metadata for chain bootstrap
- `GET /v1/workspaces/:id/audit/chain` - current chain head (last hash + event id)

## Auth

Bearer JWT with `aud=pact-audit` (Mode A). Requires `admin` or `auditor` role.

## Env

- `DATABASE_URL`, `ISSUER_BASE_URL` (required)
- `AUDIT_AUDIENCE` (default `pact-audit`)
- `ENVIRONMENT`
