# @getpact/web

Dashboard Worker for Pact users. It owns Google login, session cookies, workspace status, and the product control plane.

## Commands

- `pnpm --filter @getpact/web dev` starts the Worker locally over HTTPS so Secure `__Host-` cookies work.
- `pnpm --filter @getpact/web test` runs dashboard route tests.
- `pnpm --filter @getpact/web typecheck` checks TypeScript.

## Required Environment

- `WEB_BASE_URL`
- `ISSUER_BASE_URL`
- `ADMIN_API_BASE_URL`
- `AUDIT_API_BASE_URL`
- `GOOGLE_OAUTH_CLIENT_ID`

Set `GOOGLE_OAUTH_CLIENT_ID` with `wrangler secret put GOOGLE_OAUTH_CLIENT_ID` for production. Provider tokens and Pact tokens must stay in HttpOnly cookies or server-side services. Browser JavaScript should only call same-origin dashboard endpoints.
