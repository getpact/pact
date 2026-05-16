import { describe, expect, it } from "vitest";
import { type Ed25519PublicJwk, generateEd25519Keypair } from "../ed25519.js";
import { fromBase64Url, toBase64Url } from "../hash.js";
import { sdjwt } from "../index.js";

const exportPublicJwk = async (
  key: CryptoKey,
  kid: string,
): Promise<Ed25519PublicJwk & { kid: string }> => {
  const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: jwk.x as string,
    kid,
  };
};

const baseClaims = {
  iss: "https://getpact.dev/acme",
  share_id: "shr_01J0",
  iat: 1_700_000_000,
  exp: 1_700_003_600,
};

const sampleDisclosures = [
  { name: "policy", value: { scope: ["mcp:read"], ttl: 3600 } },
  { name: "payload", value: { kind: "memory", text: "hello" } },
  { name: "origin", value: "claude-code" },
];

const newIssuer = async (kid = "iss-1") => {
  const kp = await generateEd25519Keypair();
  const jwk = await exportPublicJwk(kp.publicKey, kid);
  return { kp, jwk, kid, jwks: { keys: [jwk] } };
};

const newHolder = async () => {
  const kp = await generateEd25519Keypair();
  const jwk = await exportPublicJwk(kp.publicKey, "holder");
  return { kp, jwk };
};

describe("sd-jwt issue and verify", () => {
  it("round-trips three disclosures", async () => {
    const issuer = await newIssuer();
    const holder = await newHolder();
    const sd = await sdjwt.issueSdJwt({
      issuerPrivateKey: issuer.kp.privateKey,
      issuerKid: issuer.kid,
      issuerClaims: baseClaims,
      disclosures: sampleDisclosures,
      cnfJkt: holder.jwk,
    });
    expect(sd.endsWith("~")).toBe(true);
    expect(sd.split("~").filter((p) => p.length > 0).length).toBe(1 + sampleDisclosures.length);

    const compact = await sdjwt.signKbJwt({
      holderPrivateKey: holder.kp.privateKey,
      sdJwt: sd,
      audience: "https://recipient.example",
      nonce: "n-abc-123",
    });
    const result = await sdjwt.verifySdJwt({
      compactSdJwt: compact,
      issuerJwks: issuer.jwks,
      expectedAudience: "https://recipient.example",
      expectedNonce: "n-abc-123",
      requireKbBinding: true,
    });
    expect(result.claims.iss).toBe(baseClaims.iss);
    expect(result.disclosed.policy).toEqual({ scope: ["mcp:read"], ttl: 3600 });
    expect(result.disclosed.payload).toEqual({ kind: "memory", text: "hello" });
    expect(result.disclosed.origin).toBe("claude-code");
    expect(result.kbClaims?.aud).toBe("https://recipient.example");
    expect(result.kbClaims?.nonce).toBe("n-abc-123");
  });

  it("rejects a tampered disclosure", async () => {
    const issuer = await newIssuer();
    const holder = await newHolder();
    const sd = await sdjwt.issueSdJwt({
      issuerPrivateKey: issuer.kp.privateKey,
      issuerKid: issuer.kid,
      issuerClaims: baseClaims,
      disclosures: sampleDisclosures,
      cnfJkt: holder.jwk,
    });
    const parts = sd.split("~");
    const target = parts[2] as string;
    const raw = JSON.parse(new TextDecoder().decode(fromBase64Url(target))) as [
      string,
      string,
      unknown,
    ];
    const tampered = toBase64Url(
      new TextEncoder().encode(JSON.stringify([raw[0], raw[1], { kind: "memory", text: "evil" }])),
    );
    parts[2] = tampered;
    const tamperedSd = parts.join("~");
    const compact = await sdjwt.signKbJwt({
      holderPrivateKey: holder.kp.privateKey,
      sdJwt: tamperedSd,
      audience: "https://recipient.example",
      nonce: "n-1",
    });
    await expect(
      sdjwt.verifySdJwt({
        compactSdJwt: compact,
        issuerJwks: issuer.jwks,
        expectedAudience: "https://recipient.example",
        expectedNonce: "n-1",
        requireKbBinding: true,
      }),
    ).rejects.toThrow(/disclosure_hash_mismatch/);
  });

  it("rejects when kb-jwt is missing and binding is required", async () => {
    const issuer = await newIssuer();
    const holder = await newHolder();
    const sd = await sdjwt.issueSdJwt({
      issuerPrivateKey: issuer.kp.privateKey,
      issuerKid: issuer.kid,
      issuerClaims: baseClaims,
      disclosures: sampleDisclosures,
      cnfJkt: holder.jwk,
    });
    await expect(
      sdjwt.verifySdJwt({
        compactSdJwt: sd,
        issuerJwks: issuer.jwks,
        expectedAudience: "https://recipient.example",
        expectedNonce: "n-1",
        requireKbBinding: true,
      }),
    ).rejects.toThrow(/kb_required/);
  });

  it("rejects a kb-jwt signed by the wrong key", async () => {
    const issuer = await newIssuer();
    const holder = await newHolder();
    const attacker = await newHolder();
    const sd = await sdjwt.issueSdJwt({
      issuerPrivateKey: issuer.kp.privateKey,
      issuerKid: issuer.kid,
      issuerClaims: baseClaims,
      disclosures: sampleDisclosures,
      cnfJkt: holder.jwk,
    });
    const compact = await sdjwt.signKbJwt({
      holderPrivateKey: attacker.kp.privateKey,
      sdJwt: sd,
      audience: "https://recipient.example",
      nonce: "n-1",
    });
    await expect(
      sdjwt.verifySdJwt({
        compactSdJwt: compact,
        issuerJwks: issuer.jwks,
        expectedAudience: "https://recipient.example",
        expectedNonce: "n-1",
        requireKbBinding: true,
      }),
    ).rejects.toThrow(/kb_sig_invalid/);
  });

  it("rejects a kb-jwt with the wrong audience", async () => {
    const issuer = await newIssuer();
    const holder = await newHolder();
    const sd = await sdjwt.issueSdJwt({
      issuerPrivateKey: issuer.kp.privateKey,
      issuerKid: issuer.kid,
      issuerClaims: baseClaims,
      disclosures: sampleDisclosures,
      cnfJkt: holder.jwk,
    });
    const compact = await sdjwt.signKbJwt({
      holderPrivateKey: holder.kp.privateKey,
      sdJwt: sd,
      audience: "https://wrong.example",
      nonce: "n-1",
    });
    await expect(
      sdjwt.verifySdJwt({
        compactSdJwt: compact,
        issuerJwks: issuer.jwks,
        expectedAudience: "https://recipient.example",
        expectedNonce: "n-1",
        requireKbBinding: true,
      }),
    ).rejects.toThrow(/kb_wrong_audience/);
  });

  it("passes the nonce through for caller-managed replay checks", async () => {
    const issuer = await newIssuer();
    const holder = await newHolder();
    const sd = await sdjwt.issueSdJwt({
      issuerPrivateKey: issuer.kp.privateKey,
      issuerKid: issuer.kid,
      issuerClaims: baseClaims,
      disclosures: sampleDisclosures,
      cnfJkt: holder.jwk,
    });
    const compact = await sdjwt.signKbJwt({
      holderPrivateKey: holder.kp.privateKey,
      sdJwt: sd,
      audience: "https://recipient.example",
      nonce: "nonce-xyz",
    });
    const seen = new Set<string>();
    const first = await sdjwt.verifySdJwt({
      compactSdJwt: compact,
      issuerJwks: issuer.jwks,
      expectedAudience: "https://recipient.example",
      requireKbBinding: true,
    });
    const nonce1 = first.kbClaims?.nonce as string;
    expect(nonce1).toBe("nonce-xyz");
    seen.add(nonce1);

    const second = await sdjwt.verifySdJwt({
      compactSdJwt: compact,
      issuerJwks: issuer.jwks,
      expectedAudience: "https://recipient.example",
      requireKbBinding: true,
    });
    const nonce2 = second.kbClaims?.nonce as string;
    expect(seen.has(nonce2)).toBe(true);

    await expect(
      sdjwt.verifySdJwt({
        compactSdJwt: compact,
        issuerJwks: issuer.jwks,
        expectedAudience: "https://recipient.example",
        expectedNonce: "different-nonce",
        requireKbBinding: true,
      }),
    ).rejects.toThrow(/kb_wrong_nonce/);
  });
});
