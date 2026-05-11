# @getpact/issuer

OIDC issuer. Mints Pact JWTs from Google identity, redeems refresh tokens, serves per-workspace JWKS.

## Endpoints

- `POST /v1/workspaces` - bootstrap a workspace + admin user
- `POST /v1/oauth/google/exchange` - exchange Google PKCE code for Pact JWT
- `POST /v1/refresh` - redeem refresh token (audience-bound)
- `POST /v1/dev/issue` - dev/test issuer, gated by `DEV_ISSUE_SECRET` outside test env
- `GET  /v1/workspaces/:id/.well-known/jwks.json` - JWT signing keys
- `GET  /v1/workspaces/:id/.well-known/audit-jwks.json` - audit signing keys

## Env

- `DATABASE_URL` - Postgres URL
- `MEK` - workspace key-wrap master key, base64
- `ISSUER_BASE_URL` - canonical issuer URL embedded in `iss` claim
- `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET`
- `DEV_ISSUE_SECRET` - required outside test/dev to expose `/v1/dev/issue`
- `ENVIRONMENT` - `production` enables prod-only guards
