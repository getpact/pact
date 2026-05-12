# Pact v1 status

Snapshot of what is shipped today vs the v1.0 plan in `_bmad-output/planning-artifacts/sprint-plan.md`. Updated as commits land. Useful for design-partner calls so you can answer "what works today" honestly.

Last updated: 2026-05-11.

## Ready to demo today

- Workspace bootstrap, Google OAuth sign-in, dev-issue path (issuer)
- JWT verification with per-workspace JWKS, audience binding, mode binding (verifier)
- Admin: users, groups, members, policies (versioned), revocations, invites, brains, brain credentials (admin-api)
- Mode B Proxy: gateway forwards authorized requests to upstream brains, audits attempt and outcome, enforces SSRF guards, path traversal block, redirect block, configurable upstream timeout, request and response header allowlists, bearer credential injection
- MCP server: tool registry with 4 built-in pact tools, Slack adapter with auth.test + channels.list, Google Drive adapter with files.list + file.get, workspace-scoped tool authorization, optional admin/auditor role guards on policy and audit tools
- Web dashboard: Google sign-in, Drive connect/disconnect, workspace status, MCP endpoint display, and same-origin `pact.whoami` MCP smoke test
- Audit chain: hash-linked + Ed25519 signed events, advisory-lock ordered, transactional with mutations (fail-closed)
- CLI: `pact init`, `pact login` (Google OAuth loopback), `pact refresh`, `pact mcp install` (Claude Code), `pact audit verify`, `pact audit checkpoint`
- Vault: per-secret DEK + AAD-bound MEK wrap; brain credentials keyed by brain id; refresh + rotate paths
- DB: RLS on all tenant tables; `pact_app` runtime role with NOBYPASSRLS; per-workspace advisory locks; runtime assertion that workers never run as the `pact` admin role in production
- CI: green on Cloudflare Workers build, lint, typecheck, real-Postgres integration tests (11 DB-gated suites enforced via `scripts/check-db-tests-ran.mjs`)
- Deploy gates: `pnpm check:cloudflare` validates wrangler config (production env, workers_dev=false, observability, routes, narrow upstream host allowlist, no dangerous forwarded headers, VERIFIER_SERVICE service binding); `pnpm check:cloudflare:gateway` adds Cloudflare Zero Trust Gateway egress policy verification (action=block, structural CIDR check across all reserved ranges, IPv6 ULA + multicast + link-local)
- Security docs: `SECURITY.md` (threat model + accepted residual risks), `docs/runbook/mek-rotation.md` (MEK rotation procedure using `pnpm --filter @getpact/db mek:rewrap`)

## What is not yet shipped

- Drive RAG indexing/search (Drive OAuth, token refresh, and raw file MCP tools are shipped; chunking, embeddings, and retrieval are not)
- Slack rate-limited mode + Marketplace submission (Week 7, not started)
- Mode B partner SDK integration (Week 8, depends on signed LOI)
- External invite redemption end-to-end (Week 9, admin POST exists, redeem flow stubbed)
- Audit chain JSON export for offline archival (Week 10, `pact audit checkpoint` ships signed head; full event export is open work)
- Python SDK (Week 11, placeholder package; `pyproject.toml` says not functional)
- Pen test (Week 11, operator action)
- Cloudflare staging deploy (operator-blocked on real Cloudflare account credentials)
- Slack Marketplace approval (depends on submission)
- SOC 2 evidence collection (Week 11)

## Architectural constraints (accepted residual)

- Single global MEK across all workspaces. Per-workspace MEK is a v2 target. SOC 2 C3.4 evidence flag.
- Token revocation propagates within 60 seconds (KV cache TTL).
- RLS depends on operator running runtime queries under `pact_app`, not `pact` admin. Enforced at runtime in production via `assertSafeRuntimeDbRole` but not at the database layer.
- DNS rebinding against gateway upstreams is mitigated only by Cloudflare Zero Trust Gateway egress policy (deploy-time), not in Worker code.
- Verifier service token in non-production deploys is optional. Set `VERIFIER_SERVICE_TOKEN` before any non-prod environment receives real traffic.

## How a design partner uses Pact today

1. Read `docs/quickstart.md`. 5 minutes from clone to first audited gateway call against `httpbin.org`.
2. Replace `httpbin.org` brain with their own internal API or one of the planned Slack adapters.
3. Wire their Claude Code or Cursor MCP client to the workspace MCP URL.
4. Use `pact invite founder-friend@vc.com --resource doc:abc --ttl 1d` to scope an external collaborator (issuer minting path works; redeem flow is the gap).
5. Read audit chain via `pact audit verify <workspaceId>` and confirm tamper-evidence.

## What to ask design partners on first call

Source `_bmad-output/planning-artifacts/founder-dms.md` for opener. On the call:

- 0-3 pain rubric: have they hit the per-user-scope problem in the last 30 days? Counted as 3 if a specific story; 2 if a near-miss; 1 if they think it might happen; 0 if "we have not thought about it".
- Mode A vs Mode B preference. Do they want reference adapters (Slack + Drive) or proxy-in-front-of-our-brain?
- Brain integration: gbrain, Hyperspell, OpenClaw, in-house, or none?
- Buying signals: existing auth budget line, vendor relationship pattern, willingness to integrate vs pre-built.
- LOI candidate yes/no after the call.

## How to convert a call to a design partner

1. Send `docs/quickstart.md` link + a 60-second one-pager extract.
2. Offer to run the quickstart with them in a 30-minute followup, end with their first audited tool call.
3. Confirm 7-day production-ish trial.
4. Track in `_bmad-output/planning-artifacts/founder-targets.md` until LOI signed.

## Cut decisions made

- `scopeInjectionTemplate` + `responseFilter` brain schema columns dropped without implementation (migration `0018_drop_brain_dead_columns.sql`). Mode B Proxy ships as plain authorized forward without per-brain scope injection or response shaping. Document this gap to design partners considering Mode B.
- Brain soft-delete deferred; admin DELETE remains hard-delete despite the partial-unique index on `status='active'`. Partial-unique is dead code until soft-delete ships.
- Tarball cleanliness verified for the 3 OSS packages (`@getpact/adapter-sdk`, `@getpact/adapter-slack`, `@getpact/verifier-sdk`). CJS dual-build deferred; consumers must use ESM.
