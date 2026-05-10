# Pact security model

Threat model and accepted gaps for the gateway, verifier, admin, audit, and issuer services.

## Threat model

- Adversary can reach all Worker routes from the public internet.
- Adversary can register their own workspaces and obtain valid tokens for those workspaces.
- Adversary cannot obtain a workspace MEK (held only by the operator) or a workspace signing key (wrapped at rest with MEK).
- Adversary may attempt: token forgery, replay, cross-workspace token reuse, audit chain tampering, SSRF via brain config, quota exhaustion, audit fail-open exploitation.

## Defenses in place

- JWT signed with workspace Ed25519 key. Token mode (A/B) bound at issue. Audience binding enforced at issue + verify + admin/audit/mcp auth.
- Refresh token redemption binds workspace + audience.
- jti revocation: verifier checks `revoked_jtis` per workspace; KV cache TTL 60s.
- Audit chain: hash-linked + signed events under workspace audit signing key, ordered by `audit_seq` with `pg_advisory_xact_lock` per workspace.
- Admin mutations write audit in the SAME transaction as the mutation; audit failure rolls back mutation and returns 503.
- Gateway pre-verifier audits flag pre-verifier denials by omitting `actor_id` (unverified subject cannot poison audit actor).
- Vault: per-secret DEK wrapped by workspace MEK with AAD bound to workspace + kind + target.
- Keystore signing keys wrapped with AAD bound to workspace + kind; backward-compat rewrap holds row lock.
- SSRF guard: brain `baseUrl` and gateway upstream URL parsed at request handler entry; private hosts, IPv6, link-local, RFC1918, and metadata IPs rejected.
- Gateway path traversal: percent-decoded segment check rejects `.`, `..`, embedded `/` or `\`.
- Outbound header strip: Authorization, Cookie, x-api-key, x-forwarded-*, method override headers blocked on forwarded request and response.
- Rate limit: DB-backed UPSERT per `(workspace_id, brain_kind, client_ip)` bucket; coarse pre-verifier check before verifier RPC.
- Cheap-checks-first: bearer parse, JWT decode, workspace param vs JWT org claim, brain existence, rate limit all run before verifier call.
- TLS termination at Cloudflare; HSTS in production; CSP `default-src 'none'` and no-referrer everywhere.

## Accepted residual risk

### 1. DNS rebinding against gateway upstreams
- `assertSafeUpstreamUrl` validates the host string at parse time. `fetch` re-resolves DNS at request time.
- Workers do not expose a DNS resolver hook, so post-DNS IP validation cannot happen inside the Worker.
- Mitigation: deploy-time Cloudflare Zero Trust egress policy (operator responsibility). `scripts/deploy-cloudflare.sh` requires `PACT_GATEWAY_EGRESS_POLICY_READY=true` as a guardrail.
- Same exposure applies to the gateway-to-verifier and mcp-to-verifier fetches if `VERIFIER_URL` is ever pointed at an attacker-controlled DNS.

### 2. Verifier public oracle in non-production
- The verifier service-token gate is mandatory only when `ENVIRONMENT === "production"`. Non-prod deploys without `VERIFIER_SERVICE_TOKEN` will accept anonymous `POST /v1/verify` calls.
- Acceptable for local dev, staging without customer data. Operators must set the secret before pointing real users at a non-prod environment.

### 3. Rate-limit client key spoofing
- Pre-verifier rate-limit key includes `cf-connecting-ip` or `x-forwarded-for`. In environments without Cloudflare in front, `x-forwarded-for` is client-controlled and can be spoofed to exhaust a victim's bucket.
- Acceptable behind Cloudflare (only `cf-connecting-ip` is trusted).
- Local dev and tests bypass rate limiting (`ENVIRONMENT === "test"`).

### 4. Token replay window
- jti revocation cache TTL is 60s. Revoking a token may take up to 60s to propagate to all verifier instances in production.

### 5. Verifier-side workspace probing
- Verifier looks up workspace signing keys before verifying the JWT signature. An attacker who knows or guesses a workspace UUID can probe for its existence by observing 401 vs other errors. Listed workspaces are not user-discoverable elsewhere; impact is enumeration only.

## Out of scope

- DDoS protection at the L3/L4 layer (Cloudflare responsibility).
- Backend Postgres tenant isolation beyond RLS + workspace-scoped advisory locks. Operator must run Pact's Postgres with `pact_app` role for runtime queries; `pact` admin role bypasses RLS and must only be used for migrations.
- MEK key management. Operators must rotate MEK out-of-band; Pact does not include an HSM or KMS integration in v1.

## Reporting

Send reports to security@getpact.dev. PGP key TBD before v1.0.
