# @getpact/keystore

Per-workspace Ed25519 signing keys for JWT issuance and audit chain signing. Private keys are wrapped with the master encryption key (MEK) using AES-GCM and stored in the `workspace_signing_keys` table.

```ts
import { createSigningKey, loadActiveSigningKey, listVerifyingKeys, rotateSigningKey } from "@getpact/keystore";

const created = await createSigningKey(tx, { workspaceId, kind: "jwt", rawMek });
const active = await loadActiveSigningKey(tx, workspaceId, "jwt", rawMek);
const all = await listVerifyingKeys(tx, workspaceId, "jwt");
await rotateSigningKey(tx, { workspaceId, kind: "jwt", rawMek });
```

Rotation marks the previous key with `valid_for_signing_until = now()` and grants a verification grace window (default 7 days) so older tokens still verify while in flight. `rotateStaleKeys` walks all workspaces and rotates keys older than the configured age.
