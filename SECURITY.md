# Pact security model

Threat model and accepted gaps for the gateway, verifier, admin, audit, and issuer services.

## Threat model

- Adversary can reach all Worker routes from the public internet.
- Adversary can register their own workspaces and obtain valid tokens for those workspaces.
- Adversary cannot obtain the deployment MEK (held only by the operator) or a workspace signing key (wrapped at rest with MEK).
- Adversary may attempt: token forgery, replay, cross-workspace token reuse, audit chain tampering, SSRF via brain config, quota exhaustion, audit fail-open exploitation.

## Defenses in place

- JWT signed with workspace Ed25519 key. Token mode (A/B) bound at issue. Audience binding enforced at issue + verify + admin/audit/mcp auth.
- Refresh token redemption binds workspace + audience.
- Dashboard is a same-origin BFF. Browser JavaScript calls only `apps/web`; Pact access and refresh tokens stay in `__Host-` HttpOnly cookies.
- Dashboard session cookies use host-only `__Host-` names, `Secure`, `Path=/`, and `SameSite=Strict`. OAuth handoff cookies use `SameSite=Lax` because Google callback is a top-level cross-site redirect.
- Dashboard mutations require a CSRF header checked with a timing-safe compare plus exact `Origin` or `Referer` match against configured `WEB_BASE_URL`.
- Dashboard OAuth callback exchanges codes through issuer `/v1/oauth/google/session`, which requires the web service token and an exact configured redirect URI.
- Google login binds the verified Google `sub` to the workspace user on first OAuth login and rejects later subject changes for the same workspace email.
- jti revocation: verifier checks `revoked_jtis` per workspace; KV cache TTL 60s.
- Audit chain: hash-linked + signed events under workspace audit signing key, ordered by `audit_seq` with `pg_advisory_xact_lock` per workspace.
- Admin mutations write audit in the SAME transaction as the mutation; audit failure rolls back mutation and returns 503.
- Gateway only uses unsigned JWT claims for cheap syntax and workspace-route rejection. Brain lookup, rate limiting, actor attribution, and signed gateway audit rows happen after verifier allow/deny.
- Vault: per-secret DEK wrapped by the deployment MEK with AAD bound to workspace + kind + target.
- Keystore signing keys wrapped with AAD bound to workspace + kind; backward-compat rewrap holds row lock.
- SSRF guard: brain `baseUrl` and gateway upstream URL parsed at request handler entry; private hosts, IPv6, link-local, RFC1918, and metadata IPs rejected.
- Gateway path traversal: percent-decoded segment check rejects `.`, `..`, embedded `/` or `\`.
- Outbound header policy: gateway forwards only a small request header allowlist by default. Operators may add explicit safe headers via `GATEWAY_FORWARD_HEADER_ALLOWLIST`; credentials, forwarding headers, hop-by-hop headers, and method override headers are hard blocked.
- Rate limit: DB-backed UPSERT per `(workspace_id, brain_kind, client_ip)` bucket after verifier allow.
- Cheap checks before verifier: bearer parse, JWT decode, and workspace param vs JWT org claim run before verifier call. Brain existence, rate limit, and gateway audit are post-verifier to avoid signed audit rows from unsigned tokens.
- TLS termination at Cloudflare; HSTS in production; CSP `default-src 'none'` and no-referrer everywhere.

## Accepted residual risk

### 1. DNS rebinding against gateway upstreams
- `assertSafeUpstreamUrl` validates the host string at parse time. `fetch` re-resolves DNS at request time.
- Workers do not expose a DNS resolver hook, so post-DNS IP validation cannot happen inside the Worker.
- Mitigation: deploy-time Cloudflare Zero Trust egress policy (operator responsibility). `scripts/deploy-cloudflare.sh` requires `PACT_GATEWAY_EGRESS_POLICY_ID` and validates the referenced rule before gateway deploy.
- Gateway and MCP production deploys should use Cloudflare service bindings for verifier calls. `VERIFIER_URL` remains a local-dev fallback and must not be used for production internal routing.

### 2. Verifier public oracle in non-production
- The verifier service-token gate is mandatory only when `ENVIRONMENT === "production"`. Non-prod deploys without `VERIFIER_SERVICE_TOKEN` will accept anonymous `POST /v1/verify` calls.
- Acceptable for local dev, staging without customer data. Operators must set the secret before pointing real users at a non-prod environment.

### 3. Rate-limit client key spoofing
- Gateway rate-limit key includes `cf-connecting-ip` or `x-forwarded-for`. In environments without Cloudflare in front, `x-forwarded-for` is client-controlled and can be spoofed to exhaust a victim's bucket.
- Acceptable behind Cloudflare (only `cf-connecting-ip` is trusted).
- Local dev and tests bypass rate limiting (`ENVIRONMENT === "test"`).

### 4. Token replay window
- jti revocation cache TTL is 60s. Revoking a token may take up to 60s to propagate to all verifier instances in production.

### 5. Verifier-side workspace probing
- Verifier looks up workspace signing keys before verifying the JWT signature. An attacker who knows or guesses a workspace UUID can probe for its existence by observing 401 vs other errors. Listed workspaces are not user-discoverable elsewhere; impact is enumeration only.

### 6. Dashboard XSS impact
- Dashboard CSP is strict and browser code never receives Pact access or refresh tokens.
- XSS would still allow same-origin UI actions during the victim's session and can read the CSRF token returned by `/v1/session`.
- Treat any dashboard XSS as high severity. Do not add inline scripts, third-party scripts, broad `connect-src`, or token-bearing JSON responses to browser code.

### 7. Drive retrieval plaintext index
- `pact.drive.file.index` stores extracted Drive text chunks in Postgres so `pact.drive.search` can use native full-text search.
- This is plaintext customer document content, not Vault-encrypted content. Encrypting the chunk body without a separate search service would break the current Postgres FTS retrieval path.
- Mitigations in v1 beta: chunks are scoped by workspace and user, protected by RLS, purged on Drive disconnect, search requires an active Drive connection, and each returned file is revalidated against Google Drive before snippets are returned.
- The Drive RAG MCP tools are gated by `DRIVE_RAG_ENABLED=true`; production defaults to disabled until a workspace has explicitly accepted this beta data-processing boundary.
- Do not treat Drive retrieval as production-ready for regulated customer data until encrypted retrieval or a dedicated vector/search service with an explicit data-processing boundary is implemented.

## Out of scope

- DDoS protection at the L3/L4 layer (Cloudflare responsibility).
- Backend Postgres tenant isolation beyond RLS + workspace-scoped advisory locks. Operator must run Pact's Postgres with `pact_app` role for runtime queries; `pact` admin role bypasses RLS and must only be used for migrations.
- MEK key management. Pact v1 includes a raw-key rewrap tool, but not HSM or KMS integration.
- Per-workspace MEK isolation. A single deployment MEK wraps vault DEKs and signing keys in v1 beta, so MEK compromise is a deployment-wide incident. Do not handle customer production data until a KMS-backed or per-workspace wrapping design is implemented.

## Reporting

Send reports to security@getpact.dev. PGP key TBD before v1.0.
