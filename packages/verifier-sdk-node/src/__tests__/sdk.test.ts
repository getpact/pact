import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createStaticVerifier } from "../index.js";

const ISSUER = "https://issuer.test/acme";
const AUDIENCE = "pact-mcp";

const mintToken = async (
  privateKey: CryptoKey,
  kid: string,
  ttlSeconds = 60,
  overrides: Record<string, unknown> = {},
): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sub: "user-1", email: "alice@example.com", ...overrides })
    .setProtectedHeader({ alg: "EdDSA", kid })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .setJti("jti-test")
    .sign(privateKey);
};

describe("verifier sdk", () => {
  it("verifies a token signed by the matching key", async () => {
    const pair = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
    const privateKey = pair.privateKey as CryptoKey;
    const publicKey = pair.publicKey as CryptoKey;
    const token = await mintToken(privateKey, "ws-jwt-1");
    const verifier = createStaticVerifier({ publicKey, issuer: ISSUER, audience: AUDIENCE });
    const result = await verifier.verify(token);
    expect(result.payload.sub).toBe("user-1");
  });

  it("rejects a token signed by a different key", async () => {
    const a = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
    const b = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
    const token = await mintToken(a.privateKey as CryptoKey, "ws-jwt-1");
    const verifier = createStaticVerifier({
      publicKey: b.publicKey as CryptoKey,
      issuer: ISSUER,
      audience: AUDIENCE,
    });
    await expect(verifier.verify(token)).rejects.toThrow();
  });

  it("rejects expired tokens", async () => {
    const pair = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
    const privateKey = pair.privateKey as CryptoKey;
    const publicKey = pair.publicKey as CryptoKey;
    const token = await mintToken(privateKey, "ws-jwt-1", -10);
    const verifier = createStaticVerifier({ publicKey, issuer: ISSUER, audience: AUDIENCE });
    await expect(verifier.verify(token)).rejects.toThrow();
  });

  it("rejects wrong audience", async () => {
    const pair = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
    const privateKey = pair.privateKey as CryptoKey;
    const publicKey = pair.publicKey as CryptoKey;
    const token = await mintToken(privateKey, "ws-jwt-1");
    const verifier = createStaticVerifier({
      publicKey,
      issuer: ISSUER,
      audience: "wrong-audience",
    });
    await expect(verifier.verify(token)).rejects.toThrow();
  });

  it("decodeClaims returns payload claims", async () => {
    const pair = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
    const privateKey = pair.privateKey as CryptoKey;
    const publicKey = pair.publicKey as CryptoKey;
    const token = await mintToken(privateKey, "ws-jwt-1", 60, { groups: ["eng"] });
    const verifier = createStaticVerifier({ publicKey, issuer: ISSUER, audience: AUDIENCE });
    const claims = await verifier.decodeClaims(token);
    expect(claims.email).toBe("alice@example.com");
    expect(claims.groups).toEqual(["eng"]);
  });

  it("can publish jwk via exportJWK utility", async () => {
    const pair = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
    const jwk = await exportJWK(pair.publicKey as CryptoKey);
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");
  });
});
