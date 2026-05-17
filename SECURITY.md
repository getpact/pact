# Pact security model

Threat model and accepted gaps for the gateway, verifier, admin, audit, issuer, mcp-server, and brain layers.

## Reporting

Send reports to security@getpact.dev. PGP key TBD before v1.0. Sensitive reports may also be filed as a private GitHub security advisory on the repository.

## Trust boundaries

```
browser ----- web (BFF) ----- issuer ----- postgres (RLS, MEK-wrapped keys)
                  |             |
                  |             |--- verifier (sd-jwt + kb-jwt verify, redeem state)
                  |             |
                  |             |--- mcp-server (brain.put, brain.search)
                  |             |
                  |             |--- gateway (workspace-bound upstream proxy)
                  |
                  +--- admin-api (admin mutations + audit in same tx)
```

- Browser sees the same-origin `web` BFF only. Pact access and refresh tokens stay in `__Host-` HttpOnly cookies.
- All Workers share Postgres but only ever connect with the `pact_app` role, which is bound by RLS to `app.current_workspace_id`.
- The deployment MEK is held only by the operator and wraps every workspace signing key, hmac key, and vault DEK at rest.

## Threat model per layer

### 1. Capability tokens (SD-JWT + KB-JWT)

What it protects: an agent invocation that has been delegated by a user, bound to a holder key (`cnf.jwk`), with an explicit `aud`, `tool_name`, and `scope_claim`.

Attack: a leaked SD-JWT replayed by a passive observer; a malicious holder reusing the same KB-JWT against multiple verifier instances.

Mitigations:
- Issuer JWT signed with the workspace JWT signing key (Ed25519). `kid` lookup via JWKS at the verifier (`apps/verifier/src/routes/capabilities.ts:300-305`).
- KB-JWT required (`requireKbBinding: true`), `typ` must be `kb+jwt`, signed by the holder key bound through `cnf.jwk` in the issuer payload (`apps/verifier/src/routes/capabilities.ts:307-315`, `packages/verifier-sdk-node/src/verifyPactToken.ts:267-309`).
- `sd_hash` in the KB-JWT must equal `SHA-256` over the issuer JWS plus all selected disclosures (`packages/verifier-sdk-node/src/verifyPactToken.ts:306-309`).
- Replay defense at the verifier: every successful KB verification inserts `(workspace_id, jti, kb_iat, sd_hash)` into `kbjwt_replay_log` (migration 0030). The primary key rejects duplicates; the verifier returns `kb_replay_detected` with HTTP 410 (`apps/verifier/src/routes/capabilities.ts:406-430`).
- SDK consumers can supply an in-memory `replayCache` for additional pre-network rejection (`packages/verifier-sdk-node/src/verifyPactToken.ts:325-331`).
- `kb_iat` must fall within `[now - kbIatMaxAgeSeconds, now + kbIatSkewSeconds]`. Both default to 300s.

Residual:
- Two concurrent verifier instances can both accept a replayed KB-JWT in the narrow window before the first transaction commits. The unique index serializes them; the second commit fails and is denied. There is no global lock before insert.
- The SDK `replayCache` is per-process; multi-process consumers without a shared cache rely on the verifier as the canonical replay arbiter.
- An attacker who controls both the issuer key and the holder key can mint and replay at will; this is outside the threat model.

### 2. Send caps (recipient consent for brain writes)

What it protects: a writer cannot address an arbitrary other user in a brain page audience. The recipient must mint an explicit SendCap from themselves to the writer.

Attack: a compromised or malicious workspace user writes a brain page with `audience: [<victim_user_id>]` to plant content that the victim sees as authored by them.

Mitigations:
- Table `send_caps` (migration 0031) holds issuer-grantee pairs with scope, expiry, and usage counters. RLS enforced.
- `pact.brain.put` consumes one SendCap per UUID-form audience entry in the same workspace transaction, with `FOR UPDATE SKIP LOCKED` (`apps/mcp-server/src/tools/brain.ts:202-266`).
- Self-audience entries (`entry === actorUserId`) skip the check.
- Audit events recorded for `brain.put.send_cap_required` denials and `send_cap.used` consumption.

Residual:
- Audience entries prefixed with `tier:`, `group:`, or `role:` bypass SendCap consumption (`apps/mcp-server/src/tools/brain.ts:195-200`). Group membership is itself the consent boundary; do not treat group prefixes as a per-user grant.
- Email-form or other non-UUID identifiers are treated as opaque labels, not subjects requiring consent. Anything outside `isUuid` is not enforced as a user identifier.
- A SendCap grants one write per consumption, not field-level disclosure control.

### 3. Drive attestation fence (HMAC over source provenance)

What it protects: when a brain page claims to originate from Google Drive (`gdrive://...`), the caller must prove that an authorised path (Drive ingestion) actually saw that `(source_uri, content_hash, audience)` tuple.

Attack: a tenant or compromised MCP client fabricates `source_uri: "gdrive://..."` to inject content that will later appear in search results with a credible-looking provenance.

Mitigations:
- Workspace-scoped HMAC-SHA-256 over a canonical payload of `(source_uri, content_hash, audience (sorted), issued_at)` (`packages/adapter-drive/src/attestation.ts:81-110`).
- `pact.brain.put` rejects any `gdrive://` source without a valid attestation; denial emits `brain.put.drive_attestation_invalid` audit (`apps/mcp-server/src/tools/brain.ts:351-414`).
- HMAC key per workspace, kind `adapter-drive`, wrapped with the deployment MEK + AAD `keystore:hmac:v1:<workspace>:<kind>` (`packages/keystore/src/index.ts:326-389`).
- Skew window 300s (`DRIVE_ATTESTATION_MAX_SKEW_SECONDS`). Cross-workspace replay is blocked because each workspace has its own HMAC key.

Residual:
- HMAC key compromise is unbounded forgery within that workspace. There is no per-document key derivation.
- Replay is bounded by content binding, not by a separate replay log. The verifier recomputes `content_hash` from the submitted body before calling `verifyDriveAttestation` (`apps/mcp-server/src/tools/brain.ts:348-399`); a captured attestation only validates against the exact `(source_uri, content_hash)` it was issued for, and the second insert is then rejected by the `(workspace_id, source_uri, content_hash)` lookup in `findExistingPage`. There is no MAC value at rest; the chain server-side hash plus dedup is the defense.
- Only the `gdrive://` prefix is fenced today. Other connector URIs are accepted on trust until they grow their own attestation.

### 4. Brain provenance signature

What it protects: a search hit returned by `pact.brain.search` was actually computed against this workspace's brain. The (`page_id`, `chunk_id`, `source_uri`, `chunk_index`, `issued_at`) tuple cannot be silently substituted by a downstream proxy.

Attack: a compromised middleware between brain and verifier swaps the hits and reports a different source for a chunk than what was actually retrieved.

Mitigations:
- Each hit's provenance metadata is signed with a dedicated workspace `provenance` Ed25519 signing key, JCS-canonicalized, returned as base64url (`apps/mcp-server/src/tools/brain.ts:612-695`).
- `kid` returned alongside signature so SDK can pin verification to a key from the workspace provenance JWKS (`/v1/workspaces/:id/.well-known/provenance-jwks.json`).
- SDK `verifyProvenance` checks signature, `issued_at` freshness (default 3600s), and that the provenance shape is complete (`packages/verifier-sdk-node/src/verifyProvenance.ts`).
- The provenance signing kind is distinct from `audit`, so compromise of the audit signing key no longer forges search-hit provenance and vice versa. Rotation cadence is set independently per kind.

Residual:
- Only metadata is signed, not the snippet body. An attacker who can rewrite `snippet` while preserving the signed tuple is not detected by signature verification alone. Higher-trust deployments should add chunk-content hashing into the signed payload.
- If `deps.rawMek` is unavailable, brain.search falls back to an unsigned `provenanceBase` (`apps/mcp-server/src/tools/brain.ts:627-641`). SDK consumers must reject hits with `missing_signature_fields` rather than accept them.
- Workspaces created before the provenance kind shipped have no `provenance` key. brain.search will return unsigned hits until the operator runs `pact admin backfill --what keys`, which seeds the missing key under an advisory lock. Track backfill completion before relying on signed provenance for legacy tenants.

### 5. Audit chain

- Hash-linked + Ed25519-signed events under the workspace `audit` signing key, ordered by `audit_seq` with `pg_advisory_xact_lock` per workspace (`packages/audit/src/writer.ts:29-91`).
- Genesis hash binds `(workspaceId, workspaceCreatedAt)` so the chain cannot be silently reseeded.
- Admin mutations write audit in the same transaction as the mutation; audit failure rolls back mutation and returns 503.
- Old `kbjwt_replay_log` rows are purged on a daily Worker schedule in `pact-admin-api` (`0 3 * * *` UTC, see `apps/admin-api/wrangler.toml`) via `prune_kbjwt_replay_log`; `PACT_REPLAY_RETENTION_DAYS` overrides the default 7 day window. The `pact admin prune-replay-log --older-than 7d` CLI remains for ad-hoc runs. The primary key still prevents replay regardless of retention window.

Residual: the chain is tamper-evident, not tamper-proof. An operator with direct Postgres access can rewrite history and resign forward; detection requires periodic external anchoring, which is not in v1.

### 6. Issuer, verifier, gateway, admin (existing baseline)

- JWT signed with workspace Ed25519 key. Token mode (A/B) bound at issue. Audience binding enforced at issue + verify + admin/audit/mcp auth.
- Refresh token redemption binds workspace + audience.
- Dashboard mutations require a CSRF header checked with a timing-safe compare plus exact `Origin` or `Referer` match against `WEB_BASE_URL`.
- Google login binds the verified Google `sub` to the workspace user on first OAuth login and rejects later subject changes for the same workspace email.
- `jti` revocation: verifier checks `revoked_jtis` per workspace; KV cache TTL 60s.
- Gateway only uses unsigned JWT claims for cheap syntax and workspace-route rejection. Brain lookup, rate limiting, actor attribution, and signed gateway audit rows happen after verifier allow/deny.
- SSRF guard: brain `baseUrl` and gateway upstream URL parsed at request handler entry; private hosts, IPv6, link-local, RFC1918, and metadata IPs rejected.
- Gateway path traversal: percent-decoded segment check rejects `.`, `..`, embedded `/` or `\`.
- Outbound header policy: gateway forwards only a small request header allowlist by default. Credentials, forwarding headers, hop-by-hop headers, and method override headers are hard blocked.
- Rate limit: DB-backed UPSERT per `(workspace_id, brain_kind, client_ip)` bucket after verifier allow.
- TLS at Cloudflare; HSTS in production; CSP `default-src 'none'` and no-referrer everywhere.

### 7. Key wrap

- Per-secret DEK wrapped by the deployment MEK with AAD bound to workspace + kind + target (`packages/keystore/src/index.ts:52-53`, `326-327`).
- Signing keys: AAD `keystore:v1:<workspace>:<kind>`. HMAC keys: AAD `keystore:hmac:v1:<workspace>:<kind>`.
- AAD mismatch increments a metric and fails closed unless `KEYSTORE_LEGACY_REWRAP=1` is set during a one-shot migration window.

## Accepted residual risk

### DNS rebinding against gateway upstreams
- `assertSafeUpstreamUrl` validates the host string at parse time. `fetch` re-resolves DNS at request time. Workers do not expose a DNS resolver hook, so post-DNS IP validation cannot happen inside the Worker.
- Mitigation: deploy-time Cloudflare Zero Trust egress policy. `scripts/deploy-cloudflare.sh` requires `PACT_GATEWAY_EGRESS_POLICY_ID` and validates the rule before gateway deploy.

### Verifier public oracle in non-production
- The verifier service-token gate is mandatory only when `ENVIRONMENT === "production"`. Non-prod deploys without `VERIFIER_SERVICE_TOKEN` accept anonymous `POST /v1/verify` calls. Acceptable for local dev only.

### Rate-limit client key spoofing
- Gateway rate-limit key includes `cf-connecting-ip` or `x-forwarded-for`. In environments without Cloudflare in front, `x-forwarded-for` is client-controlled. Acceptable behind Cloudflare; tests bypass rate limit (`ENVIRONMENT === "test"`).

### Token revocation propagation
- `jti` revocation cache TTL is 60s; revoking a token may take up to 60s to propagate across verifier instances.

### Verifier-side workspace probing
- Verifier looks up workspace signing keys before verifying the signature. An attacker who knows a workspace UUID can probe for existence via 401 vs other errors. Impact is enumeration only.

### Dashboard XSS impact
- Browser code never receives Pact access or refresh tokens. XSS would still allow same-origin UI actions and can read the CSRF token returned by `/v1/session`. Treat any dashboard XSS as high severity.

### Drive retrieval plaintext index
- `pact.drive.file.index` stores extracted Drive text chunks in Postgres for native FTS. This is plaintext customer document content, not Vault-encrypted.
- Mitigations in v1 beta: chunks are scoped by workspace and user, protected by RLS, purged on Drive disconnect, search requires an active Drive connection, and each returned file is revalidated against Google Drive before snippets are returned.
- Gated by `DRIVE_RAG_ENABLED=true`; production defaults to disabled.

## Out of scope (v0.1)

- Workspace owner threat: workspace owner is trusted and controls MEK and signing keys through the deployment.
- Side-channel against AES-GCM, HMAC-SHA-256, or Ed25519 primitives.
- Network MITM: TLS at Cloudflare is assumed.
- DDoS at L3/L4: Cloudflare responsibility.
- Backend Postgres isolation beyond RLS + workspace-scoped advisory locks. Operator must run runtime traffic through the `pact_app` role; `pact` admin role bypasses RLS and is for migrations only.
- MEK key management: v1 ships a raw-key rewrap tool but no HSM or KMS integration. A single deployment MEK wraps all workspace keys; MEK compromise is a deployment-wide incident. Do not handle regulated customer production data until KMS-backed or per-workspace wrapping ships.
- Global throttling of issuer/verifier: per-bucket rate limits and advisory locks exist but no global rate ceiling.
