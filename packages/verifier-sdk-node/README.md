# @getpact/verifier-sdk

Verify pact JWTs in Node.js and edge runtimes. Audit-chain verification is a separate concern handled by `@getpact/cli` (see `audit verify`).

## Status

Pre-v1.0. Not yet published.

## Usage

```ts
import { createVerifier } from "@getpact/verifier-sdk";

const verifier = createVerifier({
  jwksUrl: "https://issuer.getpact.dev/v1/workspaces/<id>/.well-known/jwks.json",
  issuer: "https://issuer.getpact.dev",
  audience: "pact-mcp",
});

const claims = await verifier.decodeClaims(token);
```

Use `createStaticVerifier` when the public key is already pinned by the caller.
