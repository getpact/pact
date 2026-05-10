# @getpact/audit

Workspace audit chain. Each event is canonicalized (JCS), hashed (SHA-256), and signed (Ed25519) by the workspace's audit key. The `prev_hash` of each event is the previous event's `this_hash`, so the chain is tamper-evident. The first event in a workspace links to a deterministic genesis hash derived from the workspace id and creation timestamp.

```ts
import { writeEvent, computeGenesisHash, verifyChain } from "@getpact/audit";

await writeEvent(tx, { workspaceId, workspaceCreatedAt, signingKeyId, signingKey, event: { ... } });

const genesis = await computeGenesisHash(workspaceId, createdAt);
const result = await verifyChain(events, jwks, genesis);
```

Subpath exports `@getpact/audit/verifier` and `@getpact/audit/genesis` are dependency-free for use in CLIs that should not pull in the postgres client.
