import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sdjwt } from "@getpact/crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type UpstreamRecord = {
  headers: Record<string, string | string[] | undefined>;
  body: string;
};

const enc = new TextEncoder();

const toBase64Url = (bytes: Uint8Array): string => {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i] as number);
  return Buffer.from(bin, "binary").toString("base64url");
};

const sha256 = async (bytes: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));

const startFakeUpstream = async (
  responder: (record: UpstreamRecord) => { status: number; body: string },
): Promise<{ url: string; records: UpstreamRecord[]; close: () => Promise<void> }> => {
  const records: UpstreamRecord[] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const record: UpstreamRecord = {
        headers: req.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      records.push(record);
      const reply = responder(record);
      res.writeHead(reply.status, { "content-type": "application/json" });
      res.end(reply.body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address() as AddressInfo;
  const close = (): Promise<void> =>
    new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  return { url: `http://127.0.0.1:${addr.port}/mcp`, records, close };
};

const generateIssuer = async (): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  kid: string;
}> => {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, kid: "issuer-test-1" };
};

const mintSdJwt = async (input: {
  issuerKey: CryptoKey;
  issuerKid: string;
  holderJwk: { kty: "OKP"; crv: "Ed25519"; x: string };
  audience: string;
}): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  const disclosures = [
    toBase64Url(
      enc.encode(JSON.stringify(["salt-scope", "scope", { tool_name: "pact.brain.search" }])),
    ),
    toBase64Url(enc.encode(JSON.stringify(["salt-agent", "agent_id", "agent-test-1"]))),
  ];
  const sdHashes = await Promise.all(
    disclosures.map(async (t) => toBase64Url(await sha256(enc.encode(t)))),
  );
  const payload = {
    iss: "https://issuer.test",
    org: "ws-1",
    sub: "agent_agent-test-1",
    jti: "jti-1",
    aud: input.audience,
    iat: now,
    exp: now + 300,
    tool_name: "pact.brain.search",
    cnf: { jwk: input.holderJwk },
    _sd: sdHashes,
    _sd_alg: "sha-256",
  };
  const header = { alg: "EdDSA", typ: "sd+jwt", kid: input.issuerKid };
  const headerB64 = toBase64Url(enc.encode(JSON.stringify(header)));
  const payloadB64 = toBase64Url(enc.encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519", input.issuerKey, enc.encode(signingInput) as BufferSource),
  );
  const jws = `${signingInput}.${toBase64Url(sig)}`;
  return `${[jws, ...disclosures].join("~")}~`;
};

const decodeJwtPayload = (jwt: string): Record<string, unknown> => {
  const parts = jwt.split(".");
  const body = Buffer.from(
    (parts[1] ?? "").replace(/-/g, "+").replace(/_/g, "/"),
    "base64",
  ).toString("utf8");
  return JSON.parse(body) as Record<string, unknown>;
};

describe("mcp bridge", () => {
  let tmp: string;
  let originalHome: string | undefined;
  let originalSdJwt: string | undefined;

  beforeEach(() => {
    originalHome = process.env.HOME;
    originalSdJwt = process.env.PACT_SD_JWT;
    tmp = mkdtempSync(join(tmpdir(), "pact-bridge-"));
    process.env.HOME = tmp;
    vi.resetModules();
  });

  afterEach(() => {
    if (originalHome) {
      process.env.HOME = originalHome;
    } else {
      delete process.env.HOME;
    }
    if (originalSdJwt !== undefined) {
      process.env.PACT_SD_JWT = originalSdJwt;
    } else {
      delete process.env.PACT_SD_JWT;
    }
    rmSync(tmp, { recursive: true, force: true });
  });

  it("signs a kb-jwt per forwarded call and rotates the nonce", async () => {
    const { loadOrCreateHolderKey } = await import("../holder-key.js");
    const holder = await loadOrCreateHolderKey();
    const issuer = await generateIssuer();
    const sd = await mintSdJwt({
      issuerKey: issuer.privateKey,
      issuerKid: issuer.kid,
      holderJwk: holder.publicJwk,
      audience: "pact-mcp",
    });

    const upstream = await startFakeUpstream(() => ({
      status: 200,
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }),
    }));

    const { startBridge } = await import("../commands/mcp-bridge.js");
    const bridge = await startBridge({
      upstream: upstream.url,
      port: 0,
      host: "127.0.0.1",
      sdJwt: sd,
      holder,
    });

    const url = `http://127.0.0.1:${bridge.port}/mcp`;
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });

    const r1 = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    expect(r1.status).toBe(200);
    const r2 = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    expect(r2.status).toBe(200);

    await bridge.close();
    await upstream.close();

    expect(upstream.records.length).toBe(2);
    const headers = upstream.records.map((r) => r.headers.authorization as string);
    for (const h of headers) {
      expect(h.startsWith("Bearer ")).toBe(true);
      const presented = h.slice("Bearer ".length);
      // sd-jwt + kb-jwt: must have the trailing tilde marker + a kb jwt segment
      expect(presented.includes("~")).toBe(true);
      const kb = presented.split("~").at(-1) ?? "";
      expect(kb.split(".").length).toBe(3);
      const kbPayload = decodeJwtPayload(kb);
      expect(kbPayload.aud).toBe("pact-mcp");
      expect(typeof kbPayload.nonce).toBe("string");
      expect(typeof kbPayload.sd_hash).toBe("string");
    }
    const nonces = headers.map((h) => {
      const kb = h.slice("Bearer ".length).split("~").at(-1) ?? "";
      return decodeJwtPayload(kb).nonce as string;
    });
    expect(nonces[0]).not.toBe(nonces[1]);
  });

  it("kb-jwt verifies under the holder cnf.jwk when paired with the sd-jwt", async () => {
    const { loadOrCreateHolderKey } = await import("../holder-key.js");
    const holder = await loadOrCreateHolderKey();
    const issuer = await generateIssuer();
    const sd = await mintSdJwt({
      issuerKey: issuer.privateKey,
      issuerKid: issuer.kid,
      holderJwk: holder.publicJwk,
      audience: "pact-mcp",
    });

    const upstream = await startFakeUpstream(() => ({ status: 200, body: "{}" }));

    const { startBridge } = await import("../commands/mcp-bridge.js");
    const bridge = await startBridge({
      upstream: upstream.url,
      port: 0,
      host: "127.0.0.1",
      sdJwt: sd,
      holder,
    });

    await fetch(`http://127.0.0.1:${bridge.port}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });

    await bridge.close();
    await upstream.close();

    const header = upstream.records[0]?.headers.authorization as string;
    const presented = header.slice("Bearer ".length);
    const jwksLookup = async () => ({
      keys: [
        {
          ...((await crypto.subtle.exportKey("jwk", issuer.publicKey)) as Record<string, unknown>),
          kid: issuer.kid,
        },
      ],
    });
    const jwks = (await jwksLookup()) as {
      keys: Array<{ kty: "OKP"; crv: "Ed25519"; x: string; kid: string }>;
    };
    const result = await sdjwt.verifySdJwt({
      compactSdJwt: presented,
      issuerJwks: jwks,
      expectedAudience: "pact-mcp",
      requireKbBinding: true,
    });
    expect(result.disclosed.agent_id).toBe("agent-test-1");
  });

  it("surfaces 401 from upstream as a jsonrpc error", async () => {
    const { loadOrCreateHolderKey } = await import("../holder-key.js");
    const holder = await loadOrCreateHolderKey();
    const issuer = await generateIssuer();
    const sd = await mintSdJwt({
      issuerKey: issuer.privateKey,
      issuerKid: issuer.kid,
      holderJwk: holder.publicJwk,
      audience: "pact-mcp",
    });

    const upstream = await startFakeUpstream(() => ({
      status: 401,
      body: JSON.stringify({ error: "unauthorized" }),
    }));

    const { startBridge } = await import("../commands/mcp-bridge.js");
    const bridge = await startBridge({
      upstream: upstream.url,
      port: 0,
      host: "127.0.0.1",
      sdJwt: sd,
      holder,
    });

    const res = await fetch(`http://127.0.0.1:${bridge.port}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/list" }),
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as {
      jsonrpc: string;
      id: number;
      error: { code: number; message: string };
    };
    expect(body.error.message).toMatch(/unauthorized/);
    expect(body.id).toBe(7);

    await bridge.close();
    await upstream.close();
  });

  it("holder key persists across bridge restarts", async () => {
    const { loadOrCreateHolderKey } = await import("../holder-key.js");
    const issuer = await generateIssuer();

    const holder1 = await loadOrCreateHolderKey();
    const sd = await mintSdJwt({
      issuerKey: issuer.privateKey,
      issuerKid: issuer.kid,
      holderJwk: holder1.publicJwk,
      audience: "pact-mcp",
    });

    const upstream = await startFakeUpstream(() => ({ status: 200, body: "{}" }));

    const { startBridge } = await import("../commands/mcp-bridge.js");
    const b1 = await startBridge({
      upstream: upstream.url,
      port: 0,
      host: "127.0.0.1",
      sdJwt: sd,
      holder: holder1,
    });
    await fetch(`http://127.0.0.1:${b1.port}/mcp`, {
      method: "POST",
      body: "{}",
      headers: { "content-type": "application/json" },
    });
    await b1.close();

    vi.resetModules();
    const { loadHolderKey } = await import("../holder-key.js");
    const holder2 = await loadHolderKey();
    expect(holder2).not.toBeNull();
    expect(holder2?.publicJwk.x).toBe(holder1.publicJwk.x);

    const b2 = await startBridge({
      upstream: upstream.url,
      port: 0,
      host: "127.0.0.1",
      sdJwt: sd,
      holder: holder2 as NonNullable<typeof holder2>,
    });
    await fetch(`http://127.0.0.1:${b2.port}/mcp`, {
      method: "POST",
      body: "{}",
      headers: { "content-type": "application/json" },
    });
    await b2.close();
    await upstream.close();

    expect(upstream.records.length).toBe(2);
  });
});
