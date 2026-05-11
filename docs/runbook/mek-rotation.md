# MEK rotation runbook

The Master Encryption Key (MEK) wraps every workspace signing key and every vault DEK. Rotating it requires re-wrapping every encrypted artifact under the new key without dropping signing capability or breaking in-flight refresh tokens.

This procedure is **not automated** in v1. Operators must execute it manually with a maintenance window.

## When to rotate

- Suspected MEK leak (operator laptop, log spill, CI artifact).
- Scheduled rotation (recommend every 12 months).
- Pact version bump that changes wrap algorithm.

## Preconditions

- All six Workers (issuer, verifier, mcp-server, admin-api, audit-api, gateway) deployed.
- Database admin access with the `pact` role (RLS bypass).
- Both `PACT_MEK_OLD` (current) and `PACT_MEK_NEW` (32-byte base64) available out-of-band.
- A maintenance window of approximately 5 minutes per 1000 workspaces.

## Procedure

### 1. Stage the new MEK

Bind `PACT_MEK_NEW` as a Cloudflare secret on every Worker:

```
wrangler secret put PACT_MEK_NEW --name pact-issuer
wrangler secret put PACT_MEK_NEW --name pact-verifier
wrangler secret put PACT_MEK_NEW --name pact-admin-api
wrangler secret put PACT_MEK_NEW --name pact-audit-api
wrangler secret put PACT_MEK_NEW --name pact-mcp-server
wrangler secret put PACT_MEK_NEW --name pact-gateway
```

Workers continue to read from `MEK` (= `PACT_MEK_OLD`) for now.

### 2. Re-wrap signing keys and vault secrets

Run a one-shot Node script (operator-owned, not in repo) that:

```
SELECT id, workspace_id, kind, private_key_wrapped FROM workspace_signing_keys;
```

For each row:
- Decrypt `private_key_wrapped` with `PACT_MEK_OLD` and AAD `keystore:v1:<workspaceId>:<kind>`.
- Re-encrypt the plaintext under `PACT_MEK_NEW` with the same AAD.
- `UPDATE workspace_signing_keys SET private_key_wrapped = $new WHERE id = $id`.

Repeat for `vault_secrets`:
```
SELECT id, workspace_id, kind, target, dek_ciphertext, ciphertext FROM vault_secrets;
```

For each row, decrypt the DEK with `PACT_MEK_OLD` + AAD `vault:v1:<workspaceId>:<kind>:<target>`, re-wrap with `PACT_MEK_NEW` + same AAD, persist. The inner `ciphertext` (DEK-encrypted plaintext) does NOT need rotation because the DEK itself was re-wrapped.

Each row updates inside its own transaction wrapped in `SELECT set_config('app.current_workspace_id', $workspaceId, true)` so RLS audit ordering stays consistent.

### 3. Swap the binding

Atomically rename: every Worker's `MEK` secret now points at `PACT_MEK_NEW` value.

The fastest pattern:
1. `wrangler secret put MEK --name <each-worker>` with new value, **in this order**: verifier, audit-api, mcp-server, gateway, admin-api, issuer.
2. Each Worker hot-reloads its secret. Workers verify against the new MEK on next request.

Reversing the order risks issuer minting tokens that other workers can't unwrap during the few-second propagation window.

### 4. Verify

Run `pnpm smoke:cloudflare PACT_SMOKE_DEV_FLOW=true PACT_SMOKE_GATEWAY_FLOW=true`. Expected: dev issue, gateway forward, and audit chain head all succeed.

If any worker still has the old MEK, those flows fail with `keystore decrypt failed`. Re-run step 3 for the lagging worker.

### 5. Tear down

Remove `PACT_MEK_NEW` and `PACT_MEK_OLD` secrets from every Worker:
```
wrangler secret delete PACT_MEK_NEW --name <each-worker>
wrangler secret delete PACT_MEK_OLD --name <each-worker>
```

Only `MEK` remains bound, now holding the rotated value.

### 6. Audit

Issue a `pact admin revoke` for any token issued before step 3 if you want to force re-authentication, or wait for natural token expiry (default 15 minutes).

## Blast radius and accepted gaps

- Pact v1 uses one global MEK across all workspaces. Per-workspace MEK is a v2 target; until then a single MEK leak compromises all stored credentials and audit signing material.
- This procedure assumes the operator has read access to Postgres with the `pact` role and out-of-band possession of both keys. There is no in-band MEK escrow.
- HSM/KMS integration is not in v1. The re-wrap script handles raw bytes in memory; operators must run it inside a secure environment and discard the script's process memory afterwards.

See [SECURITY.md](../../SECURITY.md) for the broader threat model.
