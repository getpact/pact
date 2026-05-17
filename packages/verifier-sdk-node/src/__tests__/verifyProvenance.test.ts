import canonicalize from "canonicalize";
import { exportJWK } from "jose";
import { describe, expect, it } from "vitest";
import { JwksCache } from "../jwks.js";
import { type ProvenanceSigned, verifyProvenance } from "../verifyProvenance.js";

const WORKSPACE_ID = "11111111-1111-1111-1111-111111111111";

const toBase64Url = (bytes: Uint8Array): string => {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const generateKey = async (): Promise<CryptoKeyPair> =>
  (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;

const signProvenance = async (
  privateKey: CryptoKey,
  workspaceId: string,
  base: Omit<ProvenanceSigned, "kid" | "signature">,
): Promise<ProvenanceSigned> => {
  const payload = {
    workspace_id: workspaceId,
    page_id: base.page_id,
    chunk_id: base.chunk_id,
    source_uri: base.source_uri,
    chunk_index: base.chunk_index,
    issued_at: base.issued_at,
  };
  const canonical = canonicalize(payload);
  if (canonical === undefined) throw new Error("canonicalize failed");
  const bytes = new TextEncoder().encode(canonical);
  const sig = await crypto.subtle.sign("Ed25519", privateKey, bytes as BufferSource);
  return {
    source_uri: base.source_uri,
    chunk_index: base.chunk_index,
    chunk_id: base.chunk_id,
    page_id: base.page_id,
    issued_at: base.issued_at,
    kid: "kid-1",
    signature: toBase64Url(new Uint8Array(sig)),
  };
};

const buildBase = (issuedAt: string): Omit<ProvenanceSigned, "kid" | "signature"> => ({
  source_uri: "note://alpha",
  chunk_index: 3,
  chunk_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  page_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
  issued_at: issuedAt,
});

describe("verifyProvenance", () => {
  it("verifies a fresh, untampered hit", async () => {
    const pair = await generateKey();
    const issuedAt = new Date().toISOString();
    const provenance = await signProvenance(pair.privateKey, WORKSPACE_ID, buildBase(issuedAt));
    const result = await verifyProvenance(
      { provenance },
      { workspaceId: WORKSPACE_ID, publicKey: pair.publicKey },
    );
    expect(result.ok).toBe(true);
  });

  it("rejects a hit with a tampered source_uri", async () => {
    const pair = await generateKey();
    const issuedAt = new Date().toISOString();
    const provenance = await signProvenance(pair.privateKey, WORKSPACE_ID, buildBase(issuedAt));
    const tampered: ProvenanceSigned = { ...provenance, source_uri: "note://malicious" };
    const result = await verifyProvenance(
      { provenance: tampered },
      { workspaceId: WORKSPACE_ID, publicKey: pair.publicKey },
    );
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("signature_mismatch");
  });

  it("rejects a hit with a tampered chunk_id", async () => {
    const pair = await generateKey();
    const issuedAt = new Date().toISOString();
    const provenance = await signProvenance(pair.privateKey, WORKSPACE_ID, buildBase(issuedAt));
    const tampered: ProvenanceSigned = {
      ...provenance,
      chunk_id: "cccccccc-cccc-cccc-cccc-cccccccccccc",
    };
    const result = await verifyProvenance(
      { provenance: tampered },
      { workspaceId: WORKSPACE_ID, publicKey: pair.publicKey },
    );
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("signature_mismatch");
  });

  it("rejects a hit verified with the wrong key", async () => {
    const signer = await generateKey();
    const other = await generateKey();
    const issuedAt = new Date().toISOString();
    const provenance = await signProvenance(signer.privateKey, WORKSPACE_ID, buildBase(issuedAt));
    const result = await verifyProvenance(
      { provenance },
      { workspaceId: WORKSPACE_ID, publicKey: other.publicKey },
    );
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("signature_mismatch");
  });

  it("rejects a stale issued_at beyond max age", async () => {
    const pair = await generateKey();
    const issuedAt = new Date(Date.now() - 7200 * 1000).toISOString();
    const provenance = await signProvenance(pair.privateKey, WORKSPACE_ID, buildBase(issuedAt));
    const result = await verifyProvenance(
      { provenance },
      { workspaceId: WORKSPACE_ID, publicKey: pair.publicKey, maxAgeSeconds: 3600 },
    );
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("stale");
  });

  it("rejects a hit signed for a different workspace_id", async () => {
    const pair = await generateKey();
    const issuedAt = new Date().toISOString();
    const provenance = await signProvenance(
      pair.privateKey,
      "other-workspace",
      buildBase(issuedAt),
    );
    const result = await verifyProvenance(
      { provenance },
      { workspaceId: WORKSPACE_ID, publicKey: pair.publicKey },
    );
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("signature_mismatch");
  });

  it("verifies via jwksUri when the kid matches a published key", async () => {
    const pair = await generateKey();
    const issuedAt = new Date().toISOString();
    const provenance = await signProvenance(pair.privateKey, WORKSPACE_ID, buildBase(issuedAt));
    const jwk = await exportJWK(pair.publicKey);
    const jwksUri = "https://issuer.test/v1/workspaces/ws/.well-known/provenance-jwks.json";
    const cache = new JwksCache({
      fetcher: async () => ({
        keys: [{ ...jwk, kid: provenance.kid, alg: "EdDSA", use: "sig" }],
      }),
    });
    const result = await verifyProvenance(
      { provenance },
      { workspaceId: WORKSPACE_ID, jwksUri, jwksCache: cache },
    );
    expect(result.ok).toBe(true);
  });

  it("denies with unknown_kid when the kid is not in the jwks", async () => {
    const pair = await generateKey();
    const issuedAt = new Date().toISOString();
    const provenance = await signProvenance(pair.privateKey, WORKSPACE_ID, buildBase(issuedAt));
    const jwk = await exportJWK(pair.publicKey);
    const jwksUri = "https://issuer.test/v1/workspaces/ws/.well-known/provenance-jwks.json";
    const cache = new JwksCache({
      fetcher: async () => ({
        keys: [{ ...jwk, kid: "different-kid", alg: "EdDSA", use: "sig" }],
      }),
    });
    const result = await verifyProvenance(
      { provenance },
      { workspaceId: WORKSPACE_ID, jwksUri, jwksCache: cache },
    );
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("unknown_kid");
  });

  it("denies with jwks_fetch_failed when the fetcher errors", async () => {
    const pair = await generateKey();
    const issuedAt = new Date().toISOString();
    const provenance = await signProvenance(pair.privateKey, WORKSPACE_ID, buildBase(issuedAt));
    const jwksUri = "https://issuer.test/v1/workspaces/ws/.well-known/provenance-jwks.json";
    const cache = new JwksCache({
      fetcher: async () => {
        throw new Error("network down");
      },
    });
    const result = await verifyProvenance(
      { provenance },
      { workspaceId: WORKSPACE_ID, jwksUri, jwksCache: cache },
    );
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("jwks_fetch_failed");
  });

  it("rejects a hit missing signature fields", async () => {
    const pair = await generateKey();
    const result = await verifyProvenance(
      {
        provenance: {
          source_uri: "note://no-sig",
          chunk_index: 0,
          chunk_id: null,
          page_id: null,
        } as unknown as ProvenanceSigned,
      },
      { workspaceId: WORKSPACE_ID, publicKey: pair.publicKey },
    );
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("missing_signature_fields");
  });
});
