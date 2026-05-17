import { exportJWK, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type RunningServer, runServer } from "../src/server.js";

type SignerKey = { id: string; privateKey: CryptoKey; publicKey: CryptoKey };

const ISSUER = "https://issuer.test/mode-b";
const JWKS_URI = `${ISSUER}/.well-known/jwks.json`;
const AUDIENCE = "pact-brain";
const TOOL = "brain.query";

const enc = new TextEncoder();

const toBase64Url = (bytes: Uint8Array): string => {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i] as number);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const sha256 = async (bytes: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));

const generateEd25519 = async (kid: string): Promise<SignerKey> => {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return { id: kid, privateKey: pair.privateKey, publicKey: pair.publicKey };
};

const encodeSegment = (value: unknown): string => toBase64Url(enc.encode(JSON.stringify(value)));

const signCompact = async (
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  key: CryptoKey,
): Promise<string> => {
  const signingInput = `${encodeSegment(header)}.${encodeSegment(payload)}`;
  const sig = await crypto.subtle.sign("Ed25519", key, enc.encode(signingInput) as BufferSource);
  return `${signingInput}.${toBase64Url(new Uint8Array(sig))}`;
};

const buildDisclosure = (name: string, value: unknown, salt: string): string =>
  toBase64Url(enc.encode(JSON.stringify([salt, name, value])));

type MintInput = {
  issuerKey: SignerKey;
  holderJwk: JWK;
  policy?: Record<string, unknown>;
  audience: string;
  toolName: string;
  ttlSeconds: number;
  jti?: string;
};

const mintSdJwt = async (input: MintInput): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  const disclosures = [
    buildDisclosure("scope", { tool_name: input.toolName }, "s"),
    buildDisclosure("policy", input.policy ?? {}, "p"),
  ];
  const sdHashes = await Promise.all(
    disclosures.map(async (t) => toBase64Url(await sha256(enc.encode(t)))),
  );
  const payload: Record<string, unknown> = {
    iss: ISSUER,
    org: "00000000-0000-4000-8000-00000000000a",
    sub: "agent_test",
    jti: input.jti ?? crypto.randomUUID(),
    aud: input.audience,
    iat: now,
    exp: now + input.ttlSeconds,
    tool_name: input.toolName,
    cnf: { jwk: input.holderJwk },
    _sd: sdHashes,
    _sd_alg: "sha-256",
  };
  const jws = await signCompact(
    { alg: "EdDSA", typ: "sd+jwt", kid: input.issuerKey.id },
    payload,
    input.issuerKey.privateKey,
  );
  return `${[jws, ...disclosures].join("~")}~`;
};

const signKbJwt = async (
  holderKey: CryptoKey,
  sdJwt: string,
  audience: string,
  iat?: number,
): Promise<string> => {
  const sdHash = toBase64Url(await sha256(enc.encode(sdJwt)));
  const kb = await signCompact(
    { alg: "EdDSA", typ: "kb+jwt" },
    { iat: iat ?? Math.floor(Date.now() / 1000), aud: audience, nonce: "mode-b", sd_hash: sdHash },
    holderKey,
  );
  return `${sdJwt}${kb}`;
};

const installJwksMock = (issuerKey: SignerKey): void => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    if (url === JWKS_URI) {
      const exported = (await exportJWK(issuerKey.publicKey)) as unknown as Record<string, unknown>;
      const jwk = { ...exported, kid: issuerKey.id, alg: "EdDSA", use: "sig" };
      return new Response(JSON.stringify({ keys: [jwk] }), {
        status: 200,
        headers: { "content-type": "application/jwk-set+json" },
      });
    }
    return realFetch(input as Parameters<typeof fetch>[0], init);
  }) as typeof fetch;
};

let running: RunningServer;
let baseUrl: string;
let issuerKey: SignerKey;

beforeAll(async () => {
  issuerKey = await generateEd25519("issuer-key-mode-b");
  installJwksMock(issuerKey);
  running = await runServer({
    port: 0,
    jwksUri: JWKS_URI,
    audience: AUDIENCE,
    toolName: TOOL,
    documents: [
      { id: "doc:q4-plan", title: "Q4 plan", snippet: "milestones" },
      { id: "doc:onboarding", title: "Onboarding", snippet: "day one" },
      { id: "doc:sec-review", title: "Security review", snippet: "threat model" },
    ],
  });
  baseUrl = `http://127.0.0.1:${running.port}`;
});

afterAll(async () => {
  if (running) await running.close();
});

const presentToken = async (overrides?: {
  policy?: Record<string, unknown>;
  audience?: string;
  toolName?: string;
}): Promise<{ token: string; holder: SignerKey }> => {
  const holder = await generateEd25519("holder-key");
  const holderJwk = (await exportJWK(holder.publicKey)) as JWK;
  const cnfJwk: JWK = { kty: holderJwk.kty, crv: holderJwk.crv ?? "Ed25519", x: holderJwk.x ?? "" };
  const sd = await mintSdJwt({
    issuerKey,
    holderJwk: cnfJwk,
    policy: overrides?.policy ?? { docs: ["doc:q4-plan"] },
    audience: overrides?.audience ?? AUDIENCE,
    toolName: overrides?.toolName ?? TOOL,
    ttlSeconds: 120,
  });
  const presented = await signKbJwt(holder.privateKey, sd, overrides?.audience ?? AUDIENCE);
  return { token: presented, holder };
};

type BrainResponse = {
  allow?: boolean;
  reason?: string;
  audience?: string;
  hits?: Array<{ id: string; title: string; snippet: string }>;
};

const callBrain = async (
  token: string,
  q = "q4",
): Promise<{ status: number; body: BrainResponse }> => {
  const res = await fetch(`${baseUrl}/brain/query`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ q }),
  });
  const body = (await res.json()) as BrainResponse;
  return { status: res.status, body };
};

describe("mode-b brain over HTTP", () => {
  it("allows when token verifies and filters hits to the policy docs allowlist", async () => {
    const { token } = await presentToken({ policy: { docs: ["doc:q4-plan", "doc:onboarding"] } });
    const { status, body } = await callBrain(token, "planning");
    expect(status).toBe(200);
    expect(body.allow).toBe(true);
    expect(body.audience).toBe(AUDIENCE);
    expect(Array.isArray(body.hits)).toBe(true);
    const ids = (body.hits ?? []).map((h) => h.id).sort();
    expect(ids).toEqual(["doc:onboarding", "doc:q4-plan"]);
  });

  it("returns an empty hit set when policy docs is the empty list", async () => {
    const { token } = await presentToken({ policy: { docs: [] } });
    const { status, body } = await callBrain(token);
    expect(status).toBe(200);
    expect(body.allow).toBe(true);
    expect(body.hits).toEqual([]);
  });

  it("denies with aud_mismatch when token audience does not match brain audience", async () => {
    const { token } = await presentToken({ audience: "wrong-aud" });
    const { status, body } = await callBrain(token);
    expect(status).toBe(403);
    expect(body.allow).toBe(false);
    expect(body.reason).toBe("aud_mismatch");
  });

  it("denies with tool_mismatch when the token was minted for a different tool", async () => {
    const { token } = await presentToken({ toolName: "brain.other" });
    const { status, body } = await callBrain(token);
    expect(status).toBe(403);
    expect(body.reason).toBe("tool_mismatch");
  });

  it("denies with kb_replay_detected on the second presentation of the same KB-JWT", async () => {
    const { token } = await presentToken();
    const first = await callBrain(token);
    expect(first.status).toBe(200);
    const second = await callBrain(token);
    expect(second.status).toBe(410);
    expect(second.body.reason).toBe("kb_replay_detected");
  });

  it("rejects requests without a bearer token", async () => {
    const res = await fetch(`${baseUrl}/brain/query`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ q: "anything" }),
    });
    expect(res.status).toBe(401);
  });

  it("rejects when the bearer is not a real SD-JWT", async () => {
    const { status, body } = await callBrain("not-a-jwt");
    expect(status).toBe(403);
    expect(body.allow).toBe(false);
  });
});
