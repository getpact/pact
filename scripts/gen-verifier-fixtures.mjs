#!/usr/bin/env node
// Generates the cross-language verifier conformance corpus.
//
// The Node and Python verifier SDKs re-implement the same SD-JWT + KB-JWT
// checks. Nothing else proves they agree, so both test suites replay this
// corpus and assert identical outcomes. Tokens are minted with @getpact/crypto
// (the same code the issuer uses) so the corpus pins the real wire format, not
// a hand-rolled approximation of it.
//
// Everything is deterministic: fixed key seeds, fixed disclosure salts, and a
// fixed reference clock that both suites inject. Regenerating without changing
// a case must produce a byte-identical file.
//
//   pnpm --filter @getpact/crypto build
//   node scripts/gen-verifier-fixtures.mjs

import { createPublicKey } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const distPath = resolve(root, "packages/crypto/dist/index.js");

let cryptoPkg;
try {
  cryptoPkg = await import(distPath);
} catch {
  console.error(`cannot import ${distPath}`);
  console.error("build it first: pnpm --filter @getpact/crypto build");
  process.exit(1);
}

const { sdjwt, importPrivatePkcs8, signEd25519, sha256, toBase64Url } = cryptoPkg;

const enc = new TextEncoder();

// PKCS8 v1 wrapper for a raw Ed25519 seed (RFC 8410 section 7).
const PKCS8_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

const keypairFromSeed = async (seedByte) => {
  const seed = new Uint8Array(32).fill(seedByte);
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
  const privateKey = await importPrivatePkcs8(pkcs8);
  const publicJwk = createPublicKey({
    key: Buffer.from(pkcs8),
    format: "der",
    type: "pkcs8",
  }).export({ format: "jwk" });
  return { privateKey, publicJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x } };
};

const issuer = await keypairFromSeed(0x11);
const holder = await keypairFromSeed(0x22);
const impostor = await keypairFromSeed(0x33);

const ISSUER_KID = "conformance-issuer-1";
const JWKS_URI = "https://issuer.example/v1/workspaces/ws-conformance/.well-known/jwks.json";
const WORKSPACE_ID = "8f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f";
const AUDIENCE = "pact-gateway";
const TOOL_NAME = "pact.brain.search";

// Reference clock. Both suites inject this instead of reading the wall clock.
const NOW_SECONDS = 1750000000;

const baseClaims = (overrides = {}) => ({
  iss: "https://issuer.example",
  org: WORKSPACE_ID,
  aud: AUDIENCE,
  jti: "jti-conformance-0001",
  sub: "agent_1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9",
  iat: NOW_SECONDS - 60,
  exp: NOW_SECONDS + 3600,
  ...overrides,
});

const mintSdJwt = async ({ claims, disclosures = [], cnf = holder.publicJwk, kid = ISSUER_KID }) =>
  sdjwt.issueSdJwt({
    issuerPrivateKey: issuer.privateKey,
    issuerKid: kid,
    issuerClaims: claims,
    disclosures,
    ...(cnf ? { cnfJkt: cnf } : {}),
  });

// Mirrors sdjwt.signKbJwt, except iat is supplied rather than read from the
// wall clock, and the signing key can be someone other than the holder.
const attachKbJwt = async (sdJwt, { iat, audience = AUDIENCE, key = holder.privateKey, over }) => {
  const bound = over ?? sdJwt;
  const sdHash = toBase64Url(await sha256(enc.encode(bound)));
  const header = { alg: "EdDSA", typ: "kb+jwt" };
  const payload = { iat, aud: audience, nonce: "conformance-nonce", sd_hash: sdHash };
  const head = toBase64Url(enc.encode(JSON.stringify(header)));
  const body = toBase64Url(enc.encode(JSON.stringify(payload)));
  const signature = await signEd25519(key, enc.encode(`${head}.${body}`));
  return `${sdJwt}${head}.${body}.${toBase64Url(signature)}`;
};

const replayKey = async (sdJwtWithKb, jti) => {
  const kb = sdJwtWithKb.slice(sdJwtWithKb.lastIndexOf("~") + 1);
  const sdHashInput = sdJwtWithKb.slice(0, sdJwtWithKb.length - kb.length);
  const payload = JSON.parse(Buffer.from(kb.split(".")[1], "base64url").toString("utf8"));
  const sdHash = toBase64Url(await sha256(enc.encode(sdHashInput)));
  return `${jti}:${payload.iat}:${sdHash}`;
};

const FRESH_KB_IAT = NOW_SECONDS - 10;
const cases = [];
const add = (c) => cases.push(c);

// 1. scope_claim on the issuer payload, no resource constraint to satisfy.
{
  const sd = await mintSdJwt({
    claims: baseClaims({ tool_name: TOOL_NAME, scope_claim: { tool_name: TOOL_NAME } }),
  });
  add({
    name: "allow_scope_claim_without_resource",
    description: "Issuer scope_claim carries only tool_name, so no resource match is required.",
    sdJwt: await attachKbJwt(sd, { iat: FRESH_KB_IAT }),
    options: { audience: AUDIENCE },
    expect: {
      ok: true,
      jti: "jti-conformance-0001",
      workspaceId: WORKSPACE_ID,
      audience: AUDIENCE,
      agentId: "1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9",
    },
  });
}

// 2. Disclosed scope wins over the issuer scope_claim, wildcard resource match.
{
  const sd = await mintSdJwt({
    claims: baseClaims({ tool_name: TOOL_NAME, scope_claim: { tool_name: "ignored.tool" } }),
    disclosures: [
      { name: "scope", value: { tool_name: TOOL_NAME, doc: "doc:*" }, salt: "conformance-salt-01" },
    ],
  });
  add({
    name: "allow_disclosed_scope_wildcard_resource",
    description: "Disclosed scope takes precedence and doc:* matches the requested doc.",
    sdJwt: await attachKbJwt(sd, { iat: FRESH_KB_IAT }),
    options: { audience: AUDIENCE, toolName: TOOL_NAME, resource: { doc: "doc:abc" } },
    expect: {
      ok: true,
      jti: "jti-conformance-0001",
      workspaceId: WORKSPACE_ID,
      audience: AUDIENCE,
      agentId: "1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9",
    },
  });
}

// 3. Expiry is checked against the injected clock, before audience.
{
  const sd = await mintSdJwt({
    claims: baseClaims({ exp: NOW_SECONDS - 1, scope_claim: { tool_name: TOOL_NAME } }),
  });
  add({
    name: "deny_expired",
    description: "Issuer exp is in the past relative to the reference clock.",
    sdJwt: await attachKbJwt(sd, { iat: FRESH_KB_IAT }),
    options: { audience: AUDIENCE },
    expect: { ok: false, reason: "expired" },
  });
}

// 4. Audience binding.
{
  const sd = await mintSdJwt({
    claims: baseClaims({ aud: "pact-mcp", scope_claim: { tool_name: TOOL_NAME } }),
  });
  add({
    name: "deny_aud_mismatch",
    description: "Token was issued for a different audience than the verifier expects.",
    sdJwt: await attachKbJwt(sd, { iat: FRESH_KB_IAT, audience: "pact-mcp" }),
    options: { audience: AUDIENCE },
    expect: { ok: false, reason: "aud_mismatch" },
  });
}

// 5. Holder binding is mandatory.
{
  const sd = await mintSdJwt({ claims: baseClaims({ scope_claim: { tool_name: TOOL_NAME } }) });
  add({
    name: "deny_kb_missing",
    description: "Compact form carries no KB-JWT, so the holder proved nothing.",
    sdJwt: sd,
    options: { audience: AUDIENCE },
    expect: { ok: false, reason: "kb_missing" },
  });
}

// 6. sd_hash must bind the KB-JWT to this exact SD-JWT.
{
  const sd = await mintSdJwt({ claims: baseClaims({ scope_claim: { tool_name: TOOL_NAME } }) });
  const other = await mintSdJwt({
    claims: baseClaims({ jti: "jti-conformance-0002", scope_claim: { tool_name: TOOL_NAME } }),
  });
  add({
    name: "deny_kb_binding_invalid_sd_hash",
    description: "KB-JWT was minted over a different SD-JWT, so sd_hash does not match.",
    sdJwt: await attachKbJwt(sd, { iat: FRESH_KB_IAT, over: other }),
    options: { audience: AUDIENCE },
    expect: { ok: false, reason: "kb_binding_invalid" },
  });
}

// 7. KB-JWT must be signed by the key named in cnf.jwk.
{
  const sd = await mintSdJwt({ claims: baseClaims({ scope_claim: { tool_name: TOOL_NAME } }) });
  add({
    name: "deny_kb_signature_invalid",
    description: "KB-JWT is signed by a key other than the one bound through cnf.jwk.",
    sdJwt: await attachKbJwt(sd, { iat: FRESH_KB_IAT, key: impostor.privateKey }),
    options: { audience: AUDIENCE },
    expect: { ok: false, reason: "kb_signature_invalid" },
  });
}

// 8/9. kb_iat freshness window, both edges.
{
  const sd = await mintSdJwt({ claims: baseClaims({ scope_claim: { tool_name: TOOL_NAME } }) });
  add({
    name: "deny_kb_iat_future",
    description: "kb_iat is further ahead than the permitted skew.",
    sdJwt: await attachKbJwt(sd, { iat: NOW_SECONDS + 4000 }),
    options: { audience: AUDIENCE },
    expect: { ok: false, reason: "kb_iat_invalid" },
  });
  add({
    name: "deny_kb_iat_too_old",
    description: "kb_iat is older than the permitted max age.",
    sdJwt: await attachKbJwt(sd, { iat: NOW_SECONDS - 4000 }),
    options: { audience: AUDIENCE },
    expect: { ok: false, reason: "kb_iat_invalid" },
  });
}

// 10. Issuer signature must verify under the JWKS key. The KB-JWT is minted
// over the tampered token so its binding still holds and the issuer signature
// is the only defect; flipping the trailing base64url character would not do,
// since its low bits are padding and decode to the same signature bytes.
{
  const sd = await mintSdJwt({ claims: baseClaims({ scope_claim: { tool_name: TOOL_NAME } }) });
  const [jws, ...rest] = sd.split("~");
  const [head, body, sig] = jws.split(".");
  const flipped = `${sig[0] === "A" ? "B" : "A"}${sig.slice(1)}`;
  const tampered = [`${head}.${body}.${flipped}`, ...rest].join("~");
  add({
    name: "deny_signature_invalid",
    description: "First byte of the issuer signature is altered.",
    sdJwt: await attachKbJwt(tampered, { iat: FRESH_KB_IAT }),
    options: { audience: AUDIENCE },
    expect: { ok: false, reason: "signature_invalid" },
  });
}

// 11. Anything that is not a compact SD-JWT.
add({
  name: "deny_invalid_format",
  description: "Input is not in SD-JWT compact form.",
  sdJwt: "not-a-token",
  options: { audience: AUDIENCE },
  expect: { ok: false, reason: "invalid_format" },
});

// 12. tool_name binding.
{
  const sd = await mintSdJwt({
    claims: baseClaims({ tool_name: TOOL_NAME, scope_claim: { tool_name: TOOL_NAME } }),
  });
  add({
    name: "deny_tool_mismatch",
    description: "Caller asks for a tool the token was not minted for.",
    sdJwt: await attachKbJwt(sd, { iat: FRESH_KB_IAT }),
    options: { audience: AUDIENCE, toolName: "pact.brain.put" },
    expect: { ok: false, reason: "tool_mismatch" },
  });
}

// 13/14. Resource scope: mismatched value, and a constraint left unchecked.
{
  const sd = await mintSdJwt({
    claims: baseClaims({
      tool_name: TOOL_NAME,
      scope_claim: { tool_name: TOOL_NAME, doc: "doc:abc" },
    }),
  });
  const withKb = await attachKbJwt(sd, { iat: FRESH_KB_IAT });
  add({
    name: "deny_scope_mismatch",
    description: "Requested resource is outside the scope the token grants.",
    sdJwt: withKb,
    options: { audience: AUDIENCE, toolName: TOOL_NAME, resource: { doc: "doc:zzz" } },
    expect: { ok: false, reason: "scope_mismatch" },
  });
  add({
    name: "deny_resource_required",
    description: "Token scope constrains a resource but the caller supplied none.",
    sdJwt: withKb,
    options: { audience: AUDIENCE, toolName: TOOL_NAME },
    expect: { ok: false, reason: "resource_required" },
  });
}

// 15. Replay cache already holds this presentation.
{
  const sd = await mintSdJwt({ claims: baseClaims({ scope_claim: { tool_name: TOOL_NAME } }) });
  const withKb = await attachKbJwt(sd, { iat: FRESH_KB_IAT });
  add({
    name: "deny_kb_replay_detected",
    description: "Replay cache was seeded with this exact (jti, kb_iat, sd_hash).",
    sdJwt: withKb,
    options: { audience: AUDIENCE },
    replaySeed: [await replayKey(withKb, "jti-conformance-0001")],
    expect: { ok: false, reason: "kb_replay_detected" },
  });
}

// 16. kid that the JWKS does not carry.
{
  const sd = await mintSdJwt({
    claims: baseClaims({ scope_claim: { tool_name: TOOL_NAME } }),
    kid: "conformance-issuer-unknown",
  });
  add({
    name: "deny_jwks_unknown_kid",
    description: "Issuer header names a kid that is absent from the workspace JWKS.",
    sdJwt: await attachKbJwt(sd, { iat: FRESH_KB_IAT }),
    options: { audience: AUDIENCE },
    expect: { ok: false, reason: "jwks_fetch_failed" },
  });
}

// 17. Workspace claim is load bearing for tenant isolation.
{
  const claims = baseClaims({ scope_claim: { tool_name: TOOL_NAME } });
  delete claims.org;
  const sd = await mintSdJwt({ claims });
  add({
    name: "deny_missing_org",
    description: "Issuer payload has no org claim, so the token binds to no workspace.",
    sdJwt: await attachKbJwt(sd, { iat: FRESH_KB_IAT }),
    options: { audience: AUDIENCE },
    expect: { ok: false, reason: "invalid_format" },
  });
}

const corpus = {
  version: 1,
  generator: "scripts/gen-verifier-fixtures.mjs",
  nowSeconds: NOW_SECONDS,
  jwksUri: JWKS_URI,
  jwks: { keys: [{ ...issuer.publicJwk, kid: ISSUER_KID }] },
  cases,
};

const out = resolve(root, "conformance/verifier-cases.json");
writeFileSync(out, `${JSON.stringify(corpus, null, 2)}\n`);
console.log(`wrote ${cases.length} cases to conformance/verifier-cases.json`);
