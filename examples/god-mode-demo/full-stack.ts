import { fileURLToPath } from "node:url";
import {
  type DriveAttestation,
  signDriveAttestation,
  verifyDriveAttestation,
} from "@getpact/adapter-drive/attestation";
import {
  type ProvenanceSigned,
  type ReplayCache,
  type VerifyDenied,
  type VerifyResult,
  verifyPactToken,
  verifyProvenance,
} from "@getpact/verifier-sdk";
import canonicalize from "canonicalize";
import { exportJWK, type JWK } from "jose";

const WORKSPACE_ID = "11111111-2222-4333-8444-555555555555";
const ISSUER = "https://issuer.demo/acme";
const JWKS_URI = `${ISSUER}/.well-known/jwks.json`;
const AUDIENCE_MCP = "pact-mcp";

const enc = new TextEncoder();

const log = (step: string, status: string, detail: string): void => {
  process.stdout.write(`[${step}] ${status}: ${detail}\n`);
};

const toBase64Url = (bytes: Uint8Array): string => {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i] as number);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const sha256 = async (bytes: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));

const sha256Hex = async (value: string): Promise<string> => {
  const digest = await sha256(enc.encode(value));
  let out = "";
  for (let i = 0; i < digest.length; i += 1) {
    out += (digest[i] as number).toString(16).padStart(2, "0");
  }
  return out;
};

const randomBytes = (n: number): Uint8Array => {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
};

const uuid = (): string => {
  const b = randomBytes(16);
  b[6] = ((b[6] as number) & 0x0f) | 0x40;
  b[8] = ((b[8] as number) & 0x3f) | 0x80;
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};

export type User = {
  id: string;
  email: string;
};

export type SendCap = {
  id: string;
  issuerUserId: string;
  granteeUserId: string;
  scopePattern: Record<string, unknown>;
  maxUses: number | null;
  usedCount: number;
  expiresAt: Date | null;
  revokedAt: Date | null;
};

export const mintSendCap = (input: {
  issuer: User;
  grantee: User;
  scopePattern?: Record<string, unknown>;
  maxUses?: number | null;
  ttlSeconds?: number;
}): SendCap => {
  const now = Date.now();
  return {
    id: uuid(),
    issuerUserId: input.issuer.id,
    granteeUserId: input.grantee.id,
    scopePattern: input.scopePattern ?? {},
    maxUses: input.maxUses ?? null,
    usedCount: 0,
    expiresAt: input.ttlSeconds ? new Date(now + input.ttlSeconds * 1000) : null,
    revokedAt: null,
  };
};

export type SendCapCheck =
  | { kind: "allow"; consumedCapIds: string[] }
  | { kind: "deny"; audienceUserId: string; reason: string };

export const consumeSendCaps = (
  caps: SendCap[],
  actor: User,
  audience: string[],
  now = new Date(),
): SendCapCheck => {
  const consumed: string[] = [];
  for (const audienceUserId of audience) {
    const candidates = caps.filter((c) => {
      if (c.granteeUserId !== actor.id) return false;
      if (c.issuerUserId !== audienceUserId) return false;
      if (c.revokedAt && c.revokedAt.getTime() <= now.getTime()) return false;
      if (c.expiresAt && c.expiresAt.getTime() <= now.getTime()) return false;
      if (c.maxUses !== null && c.usedCount >= c.maxUses) return false;
      return true;
    });
    const cap = candidates[0];
    if (!cap) {
      return { kind: "deny", audienceUserId, reason: "send_cap_required" };
    }
    cap.usedCount += 1;
    consumed.push(cap.id);
  }
  return { kind: "allow", consumedCapIds: consumed };
};

export type BrainPage = {
  id: string;
  sourceUri: string;
  authorUserId: string;
  audience: string[];
  content: string;
  contentHash: string;
};

export type BrainPutResult =
  | { ok: true; pageId: string; idempotent: boolean }
  | { ok: false; status: number; error: string };

export type BrainStore = {
  pages: BrainPage[];
  caps: SendCap[];
  hmacKey: Uint8Array;
};

export const newBrainStore = (caps: SendCap[]): BrainStore => ({
  pages: [],
  caps,
  hmacKey: randomBytes(32),
});

export const brainPut = async (
  store: BrainStore,
  actor: User,
  input: {
    sourceUri: string;
    content: string;
    audience: string[];
    attestation?: DriveAttestation;
  },
): Promise<BrainPutResult> => {
  if (input.sourceUri.startsWith("gdrive://")) {
    if (!input.attestation) {
      return { ok: false, status: 403, error: "drive_attestation_invalid: missing" };
    }
    const contentHash = await sha256Hex(input.content);
    const verify = await verifyDriveAttestation({
      keyBytes: store.hmacKey,
      attestation: input.attestation,
      sourceUri: input.sourceUri,
      contentHash,
      audience: input.audience,
    });
    if (!verify.ok) {
      return { ok: false, status: 403, error: `drive_attestation_invalid: ${verify.reason}` };
    }
  }
  const contentHash = await sha256Hex(input.content);
  const existing = store.pages.find(
    (p) => p.sourceUri === input.sourceUri && p.contentHash === contentHash,
  );
  if (existing) {
    return { ok: true, pageId: existing.id, idempotent: true };
  }
  const cap = consumeSendCaps(store.caps, actor, input.audience);
  if (cap.kind === "deny") {
    return {
      ok: false,
      status: 403,
      error: `send_cap_required: no active SendCap from ${cap.audienceUserId} to actor`,
    };
  }
  const page: BrainPage = {
    id: uuid(),
    sourceUri: input.sourceUri,
    authorUserId: actor.id,
    audience: input.audience,
    content: input.content,
    contentHash,
  };
  store.pages.push(page);
  return { ok: true, pageId: page.id, idempotent: false };
};

export type SearchHit = {
  pageId: string;
  chunkId: string;
  sourceUri: string;
  snippet: string;
  provenance: ProvenanceSigned;
};

const signProvenance = async (
  privateKey: CryptoKey,
  kid: string,
  workspaceId: string,
  base: {
    source_uri: string;
    chunk_index: number;
    chunk_id: string | null;
    page_id: string | null;
    issued_at: string;
  },
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
  const sig = await crypto.subtle.sign(
    "Ed25519",
    privateKey,
    enc.encode(canonical) as BufferSource,
  );
  return {
    source_uri: base.source_uri,
    chunk_index: base.chunk_index,
    chunk_id: base.chunk_id,
    page_id: base.page_id,
    issued_at: base.issued_at,
    kid,
    signature: toBase64Url(new Uint8Array(sig)),
  };
};

export type SignerKey = { id: string; privateKey: CryptoKey; publicKey: CryptoKey };

export const brainSearch = async (
  store: BrainStore,
  caller: User,
  signer: SignerKey,
  query: string,
): Promise<SearchHit[]> => {
  const audienceFilter = [caller.id];
  const pages = store.pages.filter((p) => p.audience.some((aud) => audienceFilter.includes(aud)));
  const issuedAt = new Date().toISOString();
  const hits: SearchHit[] = [];
  for (const page of pages) {
    const chunkId = uuid();
    const provenance = await signProvenance(signer.privateKey, signer.id, WORKSPACE_ID, {
      source_uri: page.sourceUri,
      chunk_index: 0,
      chunk_id: chunkId,
      page_id: page.id,
      issued_at: issuedAt,
    });
    hits.push({
      pageId: page.id,
      chunkId,
      sourceUri: page.sourceUri,
      snippet: `${query} match in ${page.sourceUri}`,
      provenance,
    });
  }
  return hits;
};

type MintCapInput = {
  issuerKey: SignerKey;
  holderJwk: JWK;
  agentId: string;
  audience: string;
  toolName: string;
  scope: Record<string, unknown>;
  ttlSeconds: number;
  jti: string;
};

const encodeJsonSegment = (value: unknown): string =>
  toBase64Url(enc.encode(JSON.stringify(value)));

const signCompact = async (
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  key: CryptoKey,
): Promise<string> => {
  const h = encodeJsonSegment(header);
  const b = encodeJsonSegment(payload);
  const signingInput = `${h}.${b}`;
  const raw = await crypto.subtle.sign("Ed25519", key, enc.encode(signingInput) as BufferSource);
  return `${signingInput}.${toBase64Url(new Uint8Array(raw))}`;
};

const buildDisclosure = (name: string, value: unknown, salt: string): string => {
  return toBase64Url(enc.encode(JSON.stringify([salt, name, value])));
};

export const mintCapabilitySdJwt = async (input: MintCapInput): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + input.ttlSeconds;
  const disclosures = [
    buildDisclosure("scope", { tool_name: input.toolName, ...input.scope }, "salt-scope"),
    buildDisclosure("agent_id", input.agentId, "salt-agent"),
  ];
  const sdHashes = await Promise.all(
    disclosures.map(async (t) => toBase64Url(await sha256(enc.encode(t)))),
  );
  const payload: Record<string, unknown> = {
    iss: ISSUER,
    org: WORKSPACE_ID,
    sub: `agent_${input.agentId}`,
    jti: input.jti,
    aud: input.audience,
    iat: now,
    exp,
    tool_name: input.toolName,
    cnf: { jwk: input.holderJwk },
    _sd: sdHashes,
    _sd_alg: "sha-256",
  };
  const header = { alg: "EdDSA", typ: "sd+jwt", kid: input.issuerKey.id };
  const jws = await signCompact(header, payload, input.issuerKey.privateKey);
  return `${[jws, ...disclosures].join("~")}~`;
};

export const signKbJwt = async (input: {
  holderPrivateKey: CryptoKey;
  sdJwt: string;
  audience: string;
  iat?: number;
  nonce?: string;
}): Promise<string> => {
  if (!input.sdJwt.endsWith("~")) throw new Error("sdJwt must end with ~");
  const sdHash = toBase64Url(await sha256(enc.encode(input.sdJwt)));
  const iat = input.iat ?? Math.floor(Date.now() / 1000);
  const payload = {
    iat,
    aud: input.audience,
    nonce: input.nonce ?? "demo-nonce",
    sd_hash: sdHash,
  };
  const header = { alg: "EdDSA", typ: "kb+jwt" };
  const kb = await signCompact(header, payload, input.holderPrivateKey);
  return `${input.sdJwt}${kb}`;
};

export const makeReplayCache = (): ReplayCache => {
  const seen = new Set<string>();
  return {
    has: async (k) => seen.has(k),
    add: async (k) => {
      seen.add(k);
    },
  };
};

export type StaticJwksFetcher = (uri: string, kid?: string) => Promise<{ keys: JWK[] }>;

export const buildJwksFetcher = (issuerPublicKey: CryptoKey, kid: string): StaticJwksFetcher => {
  return async () => {
    const jwk = (await exportJWK(issuerPublicKey)) as JWK;
    jwk.kid = kid;
    jwk.alg = "EdDSA";
    return { keys: [jwk] };
  };
};

export const generateEd25519 = async (kid: string): Promise<SignerKey> => {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return { id: kid, privateKey: pair.privateKey, publicKey: pair.publicKey };
};

const summary = (token: string): string => `${token.slice(0, 24)}...len=${token.length}`;

export type DemoStepResult = {
  step: string;
  status: string;
  detail: Record<string, unknown>;
};

export type FullStackOutput = {
  steps: DemoStepResult[];
};

export const runFullStack = async (): Promise<FullStackOutput> => {
  const steps: DemoStepResult[] = [];
  const record = (step: string, status: string, detail: Record<string, unknown>): void => {
    steps.push({ step, status, detail });
    log(step, status, JSON.stringify(detail));
  };

  // 1. Setup
  const alice: User = { id: uuid(), email: "alice@acme.test" };
  const bob: User = { id: uuid(), email: "bob@acme.test" };
  record("setup", "ok", {
    workspace: WORKSPACE_ID,
    alice: alice.email,
    bob: bob.email,
  });

  // 2. Consent: Bob mints a SendCap granting Alice permission to address him.
  const sendCap = mintSendCap({
    issuer: bob,
    grantee: alice,
    scopePattern: { source_kind: "connector" },
    maxUses: 5,
    ttlSeconds: 3600,
  });
  const caps = [sendCap];
  record("consent", "ok", {
    cap_id: sendCap.id,
    issuer: bob.email,
    grantee: alice.email,
    max_uses: sendCap.maxUses,
  });

  // 3. Ingest: with and without drive attestation.
  const store = newBrainStore(caps);
  const sourceUri = "gdrive://doc/Q4-planning";
  const content = "Q4 planning notes for the team. Targets and milestones.";
  const audience = [bob.id];

  const denied = await brainPut(store, alice, { sourceUri, content, audience });
  record("ingest_no_attest", denied.ok ? "unexpected_ok" : "denied", {
    status: denied.ok ? 200 : denied.status,
    error: denied.ok ? null : denied.error,
  });

  const attestation = await signDriveAttestation({
    keyBytes: store.hmacKey,
    sourceUri,
    content,
    audience,
  });
  const allowed = await brainPut(store, alice, {
    sourceUri,
    content,
    audience,
    attestation,
  });
  record("ingest_with_attest", allowed.ok ? "ok" : "failed", {
    status: allowed.ok ? 201 : (allowed as { status: number }).status,
    page_id: allowed.ok ? allowed.pageId : null,
    idempotent: allowed.ok ? allowed.idempotent : null,
  });

  // 4. Audience-filtered search: Bob searches and receives the page.
  const signerKey = await generateEd25519("audit-key-1");
  const hits = await brainSearch(store, bob, signerKey, "Q4 planning");
  record("search", "ok", {
    hit_count: hits.length,
    first_source_uri: hits[0]?.sourceUri ?? null,
    kid: hits[0]?.provenance.kid ?? null,
  });

  // 5. Verify provenance signature, then tamper.
  if (!hits[0]) {
    record("verify_provenance", "skipped", { reason: "no_hits" });
  } else {
    const ok = await verifyProvenance(hits[0], {
      workspaceId: WORKSPACE_ID,
      publicKey: signerKey.publicKey,
    });
    record("verify_provenance", ok.ok ? "ok" : "failed", {
      reason: ok.ok ? null : ok.reason,
    });
    const tampered: SearchHit = {
      ...hits[0],
      provenance: { ...hits[0].provenance, source_uri: "gdrive://doc/Q4-malicious" },
    };
    const bad = await verifyProvenance(tampered, {
      workspaceId: WORKSPACE_ID,
      publicKey: signerKey.publicKey,
    });
    record("verify_provenance_tamper", bad.ok ? "unexpected_ok" : "rejected", {
      reason: bad.ok ? null : bad.reason,
    });
  }

  // 6. Mint capability + verify, then replay.
  const issuerKey = await generateEd25519("issuer-key-1");
  const holderKey = await generateEd25519("holder-key-1");
  const holderJwk = (await exportJWK(holderKey.publicKey)) as JWK;
  const cnfJwk: JWK = { kty: holderJwk.kty, crv: holderJwk.crv ?? "Ed25519", x: holderJwk.x ?? "" };

  const sd = await mintCapabilitySdJwt({
    issuerKey,
    holderJwk: cnfJwk,
    agentId: uuid(),
    audience: AUDIENCE_MCP,
    toolName: "pact.brain.search",
    scope: { resource: "drive:Q4" },
    ttlSeconds: 300,
    jti: uuid(),
  });
  const presented = await signKbJwt({
    holderPrivateKey: holderKey.privateKey,
    sdJwt: sd,
    audience: AUDIENCE_MCP,
  });

  const fetcher = buildJwksFetcher(issuerKey.publicKey, issuerKey.id);
  const { JwksCache } = await import("@getpact/verifier-sdk");
  const jwksCache = new JwksCache({ fetcher });
  const replayCache = makeReplayCache();

  const result = await verifyPactToken(presented, {
    jwksUri: JWKS_URI,
    audience: AUDIENCE_MCP,
    toolName: "pact.brain.search",
    resource: { resource: "drive:Q4" },
    jwksCache,
    replayCache,
  });
  const okResult = result as VerifyResult;
  record("capability_verify", result.ok ? "ok" : "failed", {
    token_sample: summary(presented),
    jti: result.ok ? okResult.jti : null,
    workspace: result.ok ? okResult.workspaceId : null,
    audience: result.ok ? okResult.audience : null,
  });

  const replay = await verifyPactToken(presented, {
    jwksUri: JWKS_URI,
    audience: AUDIENCE_MCP,
    toolName: "pact.brain.search",
    resource: { resource: "drive:Q4" },
    jwksCache,
    replayCache,
  });
  const denied2 = replay as VerifyDenied;
  record("capability_replay", replay.ok ? "unexpected_ok" : "rejected", {
    reason: replay.ok ? null : denied2.reason,
  });

  return { steps };
};

const isEntry = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isEntry) {
  process.env.LOG_LEVEL = process.env.LOG_LEVEL ?? "warn";
  await runFullStack();
}
