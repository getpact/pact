import { exportJWK, type JSONWebKeySet, type JWK } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import { JwksCache, type JwksFetcher } from "../jwks.js";
import { type ReplayCache, verifyPactToken } from "../verifyPactToken.js";

const ISSUER = "https://issuer.test/acme";
const JWKS_URI = "https://issuer.test/acme/.well-known/jwks.json";
const AUDIENCE = "pact-mcp";
const WORKSPACE_ID = "11111111-2222-4333-8444-555555555555";

const enc = new TextEncoder();

const toBase64Url = (bytes: Uint8Array): string => {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] as number);
  return btoa(bin).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
};

const encodeJsonSegment = (value: unknown): string =>
  toBase64Url(enc.encode(JSON.stringify(value)));

const sha256 = async (bytes: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));

const signCompact = async (
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  key: CryptoKey,
): Promise<string> => {
  const h = encodeJsonSegment(header);
  const b = encodeJsonSegment(payload);
  const signingInput = `${h}.${b}`;
  const raw = await crypto.subtle.sign(
    { name: "Ed25519" },
    key,
    enc.encode(signingInput) as BufferSource,
  );
  return `${signingInput}.${toBase64Url(new Uint8Array(raw))}`;
};

const hashDisclosure = async (token: string): Promise<string> =>
  toBase64Url(await sha256(enc.encode(token)));

const buildDisclosure = (name: string, value: unknown, salt = "salt-fixed"): string => {
  const arr: [string, string, unknown] = [salt, name, value];
  return toBase64Url(enc.encode(JSON.stringify(arr)));
};

type MintOptions = {
  issuerPrivateKey: CryptoKey;
  kid: string;
  cnfJwk: JWK;
  jti: string;
  audience?: string;
  toolName?: string;
  scope?: Record<string, unknown>;
  ttlSeconds?: number;
  agentId?: string;
};

type SignKbOptions = {
  holderPrivateKey: CryptoKey;
  sdJwt: string;
  audience: string;
  iat?: number;
  nonce?: string;
};

const mintSdJwt = async (opts: MintOptions): Promise<string> => {
  const ttl = opts.ttlSeconds ?? 60;
  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttl;
  const scope = opts.scope ?? { resource: "drive:doc-1" };
  const toolName = opts.toolName ?? "search.documents";
  const audience = opts.audience ?? AUDIENCE;
  const agentId = opts.agentId ?? "agent-uuid-123";

  const disclosureTokens = [
    buildDisclosure("scope", { tool_name: toolName, ...scope }, "salt-scope"),
    buildDisclosure("agent_id", agentId, "salt-agent"),
  ];
  const sdHashes = await Promise.all(disclosureTokens.map((t) => hashDisclosure(t)));

  const issuerPayload: Record<string, unknown> = {
    iss: ISSUER,
    org: WORKSPACE_ID,
    sub: `agent_${agentId}`,
    jti: opts.jti,
    aud: audience,
    iat: now,
    exp,
    tool_name: toolName,
    cnf: { jwk: opts.cnfJwk },
    _sd: sdHashes,
    _sd_alg: "sha-256",
  };
  const header = { alg: "EdDSA", typ: "sd+jwt", kid: opts.kid };
  const jws = await signCompact(header, issuerPayload, opts.issuerPrivateKey);
  return `${[jws, ...disclosureTokens].join("~")}~`;
};

const signKbJwt = async (opts: SignKbOptions): Promise<string> => {
  if (!opts.sdJwt.endsWith("~")) throw new Error("sdJwt must end with ~");
  const sdHash = toBase64Url(await sha256(enc.encode(opts.sdJwt)));
  const iat = opts.iat ?? Math.floor(Date.now() / 1000);
  const payload = {
    iat,
    aud: opts.audience,
    nonce: opts.nonce ?? "nonce-fixed",
    sd_hash: sdHash,
  };
  const header = { alg: "EdDSA", typ: "kb+jwt" };
  const kb = await signCompact(header, payload, opts.holderPrivateKey);
  return `${opts.sdJwt}${kb}`;
};

const makeStaticJwksFetcher =
  (jwks: JSONWebKeySet): JwksFetcher =>
  async () =>
    jwks;

const memoryReplayCache = (): ReplayCache => {
  const set = new Set<string>();
  return {
    has: async (k) => set.has(k),
    add: async (k) => {
      set.add(k);
    },
  };
};

describe("verifyPactToken", () => {
  let issuerPair: { publicKey: CryptoKey; privateKey: CryptoKey };
  let holderPair: { publicKey: CryptoKey; privateKey: CryptoKey };
  let kid: string;
  let jwksCache: JwksCache;

  beforeEach(async () => {
    issuerPair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
      "sign",
      "verify",
    ])) as { publicKey: CryptoKey; privateKey: CryptoKey };
    holderPair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
      "sign",
      "verify",
    ])) as { publicKey: CryptoKey; privateKey: CryptoKey };
    kid = "ws-jwt-1";
    const issuerPubJwk = (await exportJWK(issuerPair.publicKey)) as JWK;
    issuerPubJwk.kid = kid;
    issuerPubJwk.alg = "EdDSA";
    jwksCache = new JwksCache({
      fetcher: makeStaticJwksFetcher({ keys: [issuerPubJwk] }),
    });
  });

  const holderJwk = async (): Promise<JWK> => {
    const jwk = (await exportJWK(holderPair.publicKey)) as JWK;
    return { kty: jwk.kty, crv: jwk.crv ?? "Ed25519", x: jwk.x ?? "" };
  };

  it("verifies a well-formed capability token", async () => {
    const sd = await mintSdJwt({
      issuerPrivateKey: issuerPair.privateKey,
      kid,
      cnfJwk: await holderJwk(),
      jti: "jti-happy",
    });
    const token = await signKbJwt({
      holderPrivateKey: holderPair.privateKey,
      sdJwt: sd,
      audience: AUDIENCE,
    });

    const result = await verifyPactToken(token, {
      jwksUri: JWKS_URI,
      audience: AUDIENCE,
      toolName: "search.documents",
      resource: { resource: "drive:doc-1" },
      jwksCache,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.jti).toBe("jti-happy");
      expect(result.workspaceId).toBe(WORKSPACE_ID);
      expect(result.audience).toBe(AUDIENCE);
      expect(result.scopeClaim).toMatchObject({ resource: "drive:doc-1" });
      expect(result.agentId).toBe("agent-uuid-123");
    }
  });

  it("rejects when the issuer signature is tampered", async () => {
    const sd = await mintSdJwt({
      issuerPrivateKey: issuerPair.privateKey,
      kid,
      cnfJwk: await holderJwk(),
      jti: "jti-tamper",
    });
    const token = await signKbJwt({
      holderPrivateKey: holderPair.privateKey,
      sdJwt: sd,
      audience: AUDIENCE,
    });
    const parts = token.split(".");
    const sigB64 = parts[parts.length - 1] as string;
    const flipped = sigB64.startsWith("A") ? `B${sigB64.slice(1)}` : `A${sigB64.slice(1)}`;
    parts[parts.length - 1] = flipped;
    const bad = parts.join(".");

    const result = await verifyPactToken(bad, {
      jwksUri: JWKS_URI,
      audience: AUDIENCE,
      jwksCache,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("kb_signature_invalid");
  });

  it("rejects on audience mismatch", async () => {
    const sd = await mintSdJwt({
      issuerPrivateKey: issuerPair.privateKey,
      kid,
      cnfJwk: await holderJwk(),
      jti: "jti-aud",
    });
    const token = await signKbJwt({
      holderPrivateKey: holderPair.privateKey,
      sdJwt: sd,
      audience: AUDIENCE,
    });
    const result = await verifyPactToken(token, {
      jwksUri: JWKS_URI,
      audience: "pact-admin",
      jwksCache,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("aud_mismatch");
  });

  it("rejects an expired issuer token", async () => {
    const sd = await mintSdJwt({
      issuerPrivateKey: issuerPair.privateKey,
      kid,
      cnfJwk: await holderJwk(),
      jti: "jti-exp",
      ttlSeconds: -10,
    });
    const token = await signKbJwt({
      holderPrivateKey: holderPair.privateKey,
      sdJwt: sd,
      audience: AUDIENCE,
      iat: Math.floor(Date.now() / 1000) - 20,
    });
    const result = await verifyPactToken(token, {
      jwksUri: JWKS_URI,
      audience: AUDIENCE,
      jwksCache,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("expired");
  });

  it("rejects replayed kb-jwt when replayCache reports hit", async () => {
    const sd = await mintSdJwt({
      issuerPrivateKey: issuerPair.privateKey,
      kid,
      cnfJwk: await holderJwk(),
      jti: "jti-replay",
    });
    const token = await signKbJwt({
      holderPrivateKey: holderPair.privateKey,
      sdJwt: sd,
      audience: AUDIENCE,
    });
    const replayCache = memoryReplayCache();
    const first = await verifyPactToken(token, {
      jwksUri: JWKS_URI,
      audience: AUDIENCE,
      toolName: "search.documents",
      resource: { resource: "drive:doc-1" },
      replayCache,
      jwksCache,
    });
    expect(first.ok).toBe(true);
    const second = await verifyPactToken(token, {
      jwksUri: JWKS_URI,
      audience: AUDIENCE,
      toolName: "search.documents",
      resource: { resource: "drive:doc-1" },
      replayCache,
      jwksCache,
    });
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.reason).toBe("kb_replay_detected");
  });

  it("rejects tool_name mismatch", async () => {
    const sd = await mintSdJwt({
      issuerPrivateKey: issuerPair.privateKey,
      kid,
      cnfJwk: await holderJwk(),
      jti: "jti-tool",
      toolName: "search.documents",
    });
    const token = await signKbJwt({
      holderPrivateKey: holderPair.privateKey,
      sdJwt: sd,
      audience: AUDIENCE,
    });
    const result = await verifyPactToken(token, {
      jwksUri: JWKS_URI,
      audience: AUDIENCE,
      toolName: "write.documents",
      resource: { resource: "drive:doc-1" },
      jwksCache,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("tool_mismatch");
  });

  it("denies with resource_required when token scope demands a resource", async () => {
    const sd = await mintSdJwt({
      issuerPrivateKey: issuerPair.privateKey,
      kid,
      cnfJwk: await holderJwk(),
      jti: "jti-res",
    });
    const token = await signKbJwt({
      holderPrivateKey: holderPair.privateKey,
      sdJwt: sd,
      audience: AUDIENCE,
    });
    const result = await verifyPactToken(token, {
      jwksUri: JWKS_URI,
      audience: AUDIENCE,
      toolName: "search.documents",
      jwksCache,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("resource_required");
  });

  it("denies with scope_mismatch when resource does not satisfy scope", async () => {
    const sd = await mintSdJwt({
      issuerPrivateKey: issuerPair.privateKey,
      kid,
      cnfJwk: await holderJwk(),
      jti: "jti-scope",
      scope: { resource: "drive:doc-1" },
    });
    const token = await signKbJwt({
      holderPrivateKey: holderPair.privateKey,
      sdJwt: sd,
      audience: AUDIENCE,
    });
    const result = await verifyPactToken(token, {
      jwksUri: JWKS_URI,
      audience: AUDIENCE,
      toolName: "search.documents",
      resource: { resource: "drive:doc-99" },
      jwksCache,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("scope_mismatch");
  });

  it("returns jwks_fetch_failed when the JWKS endpoint cannot be reached", async () => {
    const sd = await mintSdJwt({
      issuerPrivateKey: issuerPair.privateKey,
      kid,
      cnfJwk: await holderJwk(),
      jti: "jti-jwks",
    });
    const token = await signKbJwt({
      holderPrivateKey: holderPair.privateKey,
      sdJwt: sd,
      audience: AUDIENCE,
    });
    const failingCache = new JwksCache({
      fetcher: async () => {
        throw new Error("network down");
      },
    });
    const result = await verifyPactToken(token, {
      jwksUri: JWKS_URI,
      audience: AUDIENCE,
      jwksCache: failingCache,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("jwks_fetch_failed");
  });
});
