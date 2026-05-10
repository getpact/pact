import { describe, expect, it } from "vitest";
import {
  decryptAesGcm,
  encryptAesGcm,
  exportAesKey,
  exportPrivatePkcs8,
  exportPublicSpki,
  generateAesKey,
  generateEd25519Keypair,
  importAesKey,
  importPrivatePkcs8,
  importPublicSpki,
  jcsCanonicalize,
  mintJwt,
  sha256,
  signEd25519,
  toHex,
  verifyEd25519,
  verifyJwt,
} from "../index.js";

describe("sha256", () => {
  it("hashes empty input deterministically", async () => {
    const h = await sha256(new Uint8Array());
    expect(toHex(h)).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("hashes 'abc' to known vector", async () => {
    const h = await sha256(new TextEncoder().encode("abc"));
    expect(toHex(h)).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});

describe("jcs canonicalization", () => {
  it("sorts object keys", () => {
    expect(jcsCanonicalize({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });

  it("matches across deep equal inputs", () => {
    const a = jcsCanonicalize({ x: { z: 3, y: 2 }, w: [1, 2] });
    const b = jcsCanonicalize({ w: [1, 2], x: { y: 2, z: 3 } });
    expect(a).toBe(b);
  });
});

describe("ed25519 sign and verify", () => {
  it("round-trips a signature", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const data = new TextEncoder().encode("hello pact");
    const sig = await signEd25519(privateKey, data);
    expect(sig.length).toBe(64);
    const ok = await verifyEd25519(publicKey, data, sig);
    expect(ok).toBe(true);
  });

  it("rejects a tampered message", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const data = new TextEncoder().encode("hello pact");
    const sig = await signEd25519(privateKey, data);
    const tampered = new TextEncoder().encode("hello tampered");
    const ok = await verifyEd25519(publicKey, tampered, sig);
    expect(ok).toBe(false);
  });

  it("re-imports exported keys and still verifies", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const priv = await exportPrivatePkcs8(privateKey);
    const pub = await exportPublicSpki(publicKey);
    const reimportedPriv = await importPrivatePkcs8(priv);
    const reimportedPub = await importPublicSpki(pub);
    const data = new TextEncoder().encode("round-trip");
    const sig = await signEd25519(reimportedPriv, data);
    const ok = await verifyEd25519(reimportedPub, data, sig);
    expect(ok).toBe(true);
  });
});

describe("aes-gcm envelope", () => {
  it("round-trips plaintext", async () => {
    const key = await generateAesKey();
    const plaintext = new TextEncoder().encode("secret value");
    const env = await encryptAesGcm(key, plaintext);
    expect(env.iv.length).toBe(12);
    const out = await decryptAesGcm(key, env);
    expect(new TextDecoder().decode(out)).toBe("secret value");
  });

  it("imports and exports a raw key without losing data", async () => {
    const key = await generateAesKey();
    const raw = await exportAesKey(key);
    expect(raw.length).toBe(32);
    const reimported = await importAesKey(raw);
    const plaintext = new TextEncoder().encode("hello");
    const env = await encryptAesGcm(reimported, plaintext);
    const out = await decryptAesGcm(key, env);
    expect(new TextDecoder().decode(out)).toBe("hello");
  });

  it("rejects tampered ciphertext", async () => {
    const key = await generateAesKey();
    const plaintext = new TextEncoder().encode("secret value");
    const env = await encryptAesGcm(key, plaintext);
    env.ciphertext[0] = (env.ciphertext[0] ?? 0) ^ 0xff;
    await expect(decryptAesGcm(key, env)).rejects.toThrow();
  });
});

describe("envelope encryption (mek wraps dek wraps secret)", () => {
  it("round-trips a workspace secret", async () => {
    const mek = await generateAesKey();
    const dek = await generateAesKey();

    const dekRaw = await exportAesKey(dek);
    const dekWrapped = await encryptAesGcm(mek, dekRaw);

    const secret = new TextEncoder().encode("workspace oauth token");
    const secretEnv = await encryptAesGcm(dek, secret);

    const dekRawAgain = await decryptAesGcm(mek, dekWrapped);
    const dekAgain = await importAesKey(dekRawAgain);
    const secretBack = await decryptAesGcm(dekAgain, secretEnv);

    expect(new TextDecoder().decode(secretBack)).toBe("workspace oauth token");
  });
});

describe("jwt mint and verify", () => {
  it("round-trips an EdDSA jwt", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const token = await mintJwt(
      { sub: "user-123", email: "alice@example.com" },
      {
        privateKey,
        kid: "ws-acme-v1",
        issuer: "https://getpact.dev/acme",
        audience: "pact-mcp",
        ttlSeconds: 60,
        jti: "01J0abc",
      },
    );
    expect(token.split(".").length).toBe(3);
    const result = await verifyJwt(token, {
      publicKey,
      issuer: "https://getpact.dev/acme",
      audience: "pact-mcp",
    });
    expect(result.payload.sub).toBe("user-123");
    expect(result.payload.email).toBe("alice@example.com");
  });

  it("rejects an expired token", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const token = await mintJwt(
      { sub: "user-1" },
      {
        privateKey,
        kid: "ws-acme-v1",
        issuer: "https://getpact.dev/acme",
        audience: "pact-mcp",
        ttlSeconds: -10,
        jti: "expired",
      },
    );
    await expect(
      verifyJwt(token, {
        publicKey,
        issuer: "https://getpact.dev/acme",
        audience: "pact-mcp",
      }),
    ).rejects.toThrow();
  });

  it("rejects a tampered audience", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const token = await mintJwt(
      { sub: "user-1" },
      {
        privateKey,
        kid: "ws-acme-v1",
        issuer: "https://getpact.dev/acme",
        audience: "pact-mcp",
        ttlSeconds: 60,
        jti: "wrong-aud",
      },
    );
    await expect(
      verifyJwt(token, {
        publicKey,
        issuer: "https://getpact.dev/acme",
        audience: "pact-other",
      }),
    ).rejects.toThrow();
  });
});
