# @getpact/vault

Per-workspace secret storage with envelope encryption. Each secret has its own AES-GCM data encryption key (DEK); the DEK is wrapped with the workspace master encryption key (MEK) and stored alongside the ciphertext in the `vault_secrets` table.

```ts
import { storeSecret, loadSecretString, listSecrets, deleteSecret } from "@getpact/vault";

await storeSecret(tx, rawMek, {
  workspaceId,
  kind: "slack",
  target: "user-token",
  plaintext: "xoxp-...",
});

const token = await loadSecretString(tx, rawMek, { workspaceId, kind: "slack", target: "user-token" });
```

Secrets are unique per `(workspace_id, kind, target)`. Re-storing the same triple rotates the underlying ciphertext and updates `rotated_at`. RLS isolates access by workspace; the `pact_app` role cannot read secrets from another workspace even with matching kind and target.
