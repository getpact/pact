# @getpact/web

Dashboard Worker for Pact users. It owns Google login, session cookies, workspace status, and the product control plane.

## Commands

- `pnpm --filter @getpact/web dev` starts the Worker locally on `http://127.0.0.1:19147`, matching the local Google OAuth client.
- `pnpm --filter @getpact/web test` runs dashboard route tests.
- `pnpm --filter @getpact/web typecheck` checks TypeScript.

## Required Environment

- `WEB_BASE_URL`
- `WEB_OAUTH_CALLBACK_PATH` - optional path override, defaults to `/v1/auth/google/callback`
- `WEB_DEV_ROUTE_ORIGIN` - optional non-production origin used only when Wrangler rewrites local requests to a custom route host
- `WEB_DEFAULT_WORKSPACE_ID` - optional demo/default workspace UUID that hides the manual workspace field
- `ISSUER_BASE_URL`
- `ADMIN_API_BASE_URL`
- `AUDIT_API_BASE_URL`
- `MCP_SERVER_BASE_URL`
- `GOOGLE_OAUTH_CLIENT_ID`
- `WEB_ISSUER_SERVICE_TOKEN`

Set `GOOGLE_OAUTH_CLIENT_ID` and `WEB_ISSUER_SERVICE_TOKEN` with `wrangler secret put` for production. The issuer must use the same `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, and `WEB_ISSUER_SERVICE_TOKEN`, and set `WEB_OAUTH_REDIRECT_URI` to `${WEB_BASE_URL}${WEB_OAUTH_CALLBACK_PATH}`. Provider tokens and Pact tokens must stay in HttpOnly cookies or server-side services. Browser JavaScript should only call same-origin dashboard endpoints.

The dashboard requests `pact-admin`, `pact-audit`, and `pact-mcp` tokens during Google login. MCP tokens stay in HttpOnly cookies and are used only by same-origin dashboard routes such as `POST /v1/mcp/test`; they are not exposed to browser JavaScript.

## Local OAuth Caveat

`pnpm --filter @getpact/web dev` uses the `local` Wrangler env on `http://127.0.0.1:19147` with callback path `/oauth/oidc/callback`, matching the local Google OAuth client. To complete login locally, run a local issuer with `WEB_OAUTH_REDIRECT_URI=http://127.0.0.1:19147/oauth/oidc/callback` and matching `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, and `WEB_ISSUER_SERVICE_TOKEN` values. Keep the client secret in ignored `.dev.vars` locally and Cloudflare secrets in production.

The dashboard always uses Secure `__Host-` cookies. The local HTTP flow is intended for Chromium/Firefox loopback development, where secure cookies are accepted on local origins.
