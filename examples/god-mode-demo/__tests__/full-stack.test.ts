import { signDriveAttestation } from "@getpact/adapter-drive/attestation";
import { verifyPactToken, verifyProvenance } from "@getpact/verifier-sdk";
import { exportJWK, type JWK } from "jose";
import { describe, expect, it } from "vitest";
import {
  brainPut,
  brainSearch,
  buildJwksFetcher,
  consumeSendCaps,
  generateEd25519,
  makeReplayCache,
  mintCapabilitySdJwt,
  mintSendCap,
  newBrainStore,
  runFullStack,
  signKbJwt,
  type User,
} from "../full-stack.js";

const aliceFixture = (): User => ({ id: "11111111-1111-1111-1111-111111111111", email: "a@x" });
const bobFixture = (): User => ({ id: "22222222-2222-2222-2222-222222222222", email: "b@x" });

describe("consent: SendCap", () => {
  it("allows when issuer matches audience and cap is active", () => {
    const alice = aliceFixture();
    const bob = bobFixture();
    const cap = mintSendCap({ issuer: bob, grantee: alice, maxUses: 1, ttlSeconds: 60 });
    const out = consumeSendCaps([cap], alice, [bob.id]);
    expect(out.kind).toBe("allow");
  });

  it("denies when no SendCap exists from audience to actor", () => {
    const alice = aliceFixture();
    const bob = bobFixture();
    const out = consumeSendCaps([], alice, [bob.id]);
    expect(out.kind).toBe("deny");
    if (out.kind === "deny") {
      expect(out.audienceUserId).toBe(bob.id);
      expect(out.reason).toBe("send_cap_required");
    }
  });

  it("denies when cap is exhausted", () => {
    const alice = aliceFixture();
    const bob = bobFixture();
    const cap = mintSendCap({ issuer: bob, grantee: alice, maxUses: 1, ttlSeconds: 60 });
    cap.usedCount = 1;
    const out = consumeSendCaps([cap], alice, [bob.id]);
    expect(out.kind).toBe("deny");
  });
});

describe("ingest: drive attestation fence", () => {
  it("denies a gdrive:// put without attestation", async () => {
    const alice = aliceFixture();
    const bob = bobFixture();
    const cap = mintSendCap({ issuer: bob, grantee: alice, maxUses: 5, ttlSeconds: 60 });
    const store = newBrainStore([cap]);
    const out = await brainPut(store, alice, {
      sourceUri: "gdrive://doc/x",
      content: "hello",
      audience: [bob.id],
    });
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.status).toBe(403);
      expect(out.error.startsWith("drive_attestation_invalid")).toBe(true);
    }
  });

  it("allows a gdrive:// put with a valid HMAC attestation", async () => {
    const alice = aliceFixture();
    const bob = bobFixture();
    const cap = mintSendCap({ issuer: bob, grantee: alice, maxUses: 5, ttlSeconds: 60 });
    const store = newBrainStore([cap]);
    const sourceUri = "gdrive://doc/x";
    const content = "hello world";
    const audience = [bob.id];
    const attestation = await signDriveAttestation({
      keyBytes: store.hmacKey,
      sourceUri,
      content,
      audience,
    });
    const out = await brainPut(store, alice, { sourceUri, content, audience, attestation });
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.idempotent).toBe(false);
      expect(out.pageId.length).toBeGreaterThan(0);
    }
  });
});

describe("search: audience filter + provenance signing", () => {
  it("returns hits Ed25519-signed by the active workspace key", async () => {
    const alice = aliceFixture();
    const bob = bobFixture();
    const cap = mintSendCap({ issuer: bob, grantee: alice, maxUses: 5, ttlSeconds: 60 });
    const store = newBrainStore([cap]);
    const sourceUri = "gdrive://doc/y";
    const content = "alpha beta gamma";
    const audience = [bob.id];
    const attestation = await signDriveAttestation({
      keyBytes: store.hmacKey,
      sourceUri,
      content,
      audience,
    });
    await brainPut(store, alice, { sourceUri, content, audience, attestation });
    const signer = await generateEd25519("kid-test");
    const hits = await brainSearch(store, bob, signer, "alpha");
    expect(hits).toHaveLength(1);
    const hit = hits[0];
    expect(hit).toBeDefined();
    if (!hit) return;
    const result = await verifyProvenance(hit, {
      workspaceId: "11111111-2222-4333-8444-555555555555",
      publicKey: signer.publicKey,
    });
    expect(result.ok).toBe(true);
  });

  it("rejects a tampered hit", async () => {
    const alice = aliceFixture();
    const bob = bobFixture();
    const cap = mintSendCap({ issuer: bob, grantee: alice, maxUses: 5, ttlSeconds: 60 });
    const store = newBrainStore([cap]);
    const sourceUri = "gdrive://doc/z";
    const content = "delta epsilon";
    const audience = [bob.id];
    const attestation = await signDriveAttestation({
      keyBytes: store.hmacKey,
      sourceUri,
      content,
      audience,
    });
    await brainPut(store, alice, { sourceUri, content, audience, attestation });
    const signer = await generateEd25519("kid-test");
    const hits = await brainSearch(store, bob, signer, "delta");
    const hit = hits[0];
    expect(hit).toBeDefined();
    if (!hit) return;
    const tampered = {
      ...hit,
      provenance: { ...hit.provenance, source_uri: "gdrive://evil" },
    };
    const bad = await verifyProvenance(tampered, {
      workspaceId: "11111111-2222-4333-8444-555555555555",
      publicKey: signer.publicKey,
    });
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.reason).toBe("signature_mismatch");
  });
});

describe("capability: verifyPactToken + replay", () => {
  it("verifies a freshly minted token, rejects on replay", async () => {
    const issuerKey = await generateEd25519("issuer-1");
    const holderKey = await generateEd25519("holder-1");
    const holderJwk = (await exportJWK(holderKey.publicKey)) as JWK;
    const cnfJwk: JWK = {
      kty: holderJwk.kty,
      crv: holderJwk.crv ?? "Ed25519",
      x: holderJwk.x ?? "",
    };
    const sd = await mintCapabilitySdJwt({
      issuerKey,
      holderJwk: cnfJwk,
      agentId: "agent-1",
      audience: "pact-mcp",
      toolName: "pact.brain.search",
      scope: { resource: "drive:doc-1" },
      ttlSeconds: 60,
      jti: "jti-1",
    });
    const presented = await signKbJwt({
      holderPrivateKey: holderKey.privateKey,
      sdJwt: sd,
      audience: "pact-mcp",
    });
    const fetcher = buildJwksFetcher(issuerKey.publicKey, issuerKey.id);
    const { JwksCache } = await import("@getpact/verifier-sdk");
    const cache = new JwksCache({ fetcher });
    const replay = makeReplayCache();
    const ok = await verifyPactToken(presented, {
      jwksUri: "https://issuer.demo/acme/.well-known/jwks.json",
      audience: "pact-mcp",
      toolName: "pact.brain.search",
      resource: { resource: "drive:doc-1" },
      jwksCache: cache,
      replayCache: replay,
    });
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.jti).toBe("jti-1");
      expect(ok.workspaceId).toBe("11111111-2222-4333-8444-555555555555");
    }
    const again = await verifyPactToken(presented, {
      jwksUri: "https://issuer.demo/acme/.well-known/jwks.json",
      audience: "pact-mcp",
      toolName: "pact.brain.search",
      resource: { resource: "drive:doc-1" },
      jwksCache: cache,
      replayCache: replay,
    });
    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.reason).toBe("kb_replay_detected");
  });
});

describe("end-to-end runFullStack", () => {
  it("drives all nine steps", async () => {
    const result = await runFullStack();
    const names = result.steps.map((s) => s.step);
    expect(names).toEqual([
      "setup",
      "consent",
      "ingest_no_attest",
      "ingest_with_attest",
      "search",
      "verify_provenance",
      "verify_provenance_tamper",
      "capability_verify",
      "capability_replay",
    ]);
    const byStep = new Map(result.steps.map((s) => [s.step, s] as const));
    expect(byStep.get("ingest_no_attest")?.status).toBe("denied");
    expect(byStep.get("ingest_with_attest")?.status).toBe("ok");
    expect(byStep.get("search")?.status).toBe("ok");
    expect(byStep.get("verify_provenance")?.status).toBe("ok");
    expect(byStep.get("verify_provenance_tamper")?.status).toBe("rejected");
    expect(byStep.get("capability_verify")?.status).toBe("ok");
    expect(byStep.get("capability_replay")?.status).toBe("rejected");
  });
});
