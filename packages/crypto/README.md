# @getpact/crypto

WebCrypto wrappers used across Pact. Runs unchanged in Node 22+, Cloudflare Workers, and any modern browser. AES-GCM helpers (`encryptAesGcm`, `decryptAesGcm`, `generateAesKey`, `importAesKey`), Ed25519 signing (`signEd25519`, `verifyEd25519`, `generateEd25519Keypair`), JWT issuance and verification with EdDSA, JCS canonicalization (`jcsBytes`), SHA-256, and base64/hex encoders.

```ts
import { issueJwt, verifyJwt, generateEd25519Keypair } from "@getpact/crypto";

const { privateKey, publicKey } = await generateEd25519Keypair();
const token = await issueJwt({ sub: "u1" }, { privateKey, kid: "k1", issuer: "i", audience: "a", ttlSeconds: 60 });
const { payload } = await verifyJwt(token, { publicKey, issuer: "i", audience: "a" });
```

Depends on `jose` and `canonicalize`.
