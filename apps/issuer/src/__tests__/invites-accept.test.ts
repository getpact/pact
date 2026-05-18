import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { exportAesKey, generateAesKey, toBase64 } from "@getpact/crypto";
import { createClient } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { adminApiApp as adminApp } from "@getpact/test-harness";
import { eq } from "drizzle-orm";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import issuerApp from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const CLIENT_ID = "test-google-client";

run("issuer invite accept", () => {
  const adminDb = createClient(url as string);
  const cleanup: string[] = [];

  let googlePrivate: CryptoKey;
  let googleJwk: Awaited<ReturnType<typeof exportJWK>>;
  const kid = "mock-google-key";
  let server: ReturnType<typeof createServer>;
  let baseUrl: string;
  let googleIssuerHost: string;
  let recipientPubJwk: Record<string, unknown>;

  beforeAll(async () => {
    const pair = await generateKeyPair("RS256", { extractable: true });
    googlePrivate = pair.privateKey as CryptoKey;
    googleJwk = await exportJWK(pair.publicKey as CryptoKey);
    googleJwk.kid = kid;
    googleJwk.alg = "RS256";
    googleJwk.use = "sig";

    const recipientPair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const exported = (await crypto.subtle.exportKey("jwk", recipientPair.publicKey)) as {
      x?: string;
    };
    recipientPubJwk = { kty: "OKP", crv: "Ed25519", x: exported.x as string };

    server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const path = req.url ?? "";
      if (path === "/jwks" && req.method === "GET") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ keys: [googleJwk] }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((resolve) => server.listen(0, () => resolve()));
    const addr = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${addr.port}`;
    googleIssuerHost = baseUrl;
  });

  afterAll(
    () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  );

  afterEach(async () => {
    while (cleanup.length > 0) {
      const id = cleanup.pop();
      if (!id) continue;
      try {
        await adminDb.delete(workspaces).where(eq(workspaces.id, id));
      } catch {}
    }
  });

  const buildEnv = async () => {
    const mek = await generateAesKey();
    return {
      DATABASE_URL: url as string,
      MEK: toBase64(await exportAesKey(mek)),
      GOOGLE_OAUTH_CLIENT_ID: CLIENT_ID,
      GOOGLE_OAUTH_CLIENT_SECRET: "test-secret",
      GOOGLE_JWKS_URI: `${baseUrl}/jwks`,
      GOOGLE_ISSUER: googleIssuerHost,
      ISSUER_BASE_URL: "https://issuer.test/acme",
      ADMIN_AUDIENCE: "pact-admin",
      ENVIRONMENT: "test",
      ENABLE_DEV_ISSUE: "true",
      PACT_ALLOW_UNAUTHED_WORKSPACE_CREATE: "true",
    };
  };

  const buildIdToken = async (
    overrides: Record<string, unknown> = {},
    subject = "google-sub-1",
  ): Promise<string> => {
    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
      email: "vc@example.com",
      email_verified: true,
    };
    Object.assign(claims, overrides);
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid })
      .setIssuer(googleIssuerHost)
      .setAudience(CLIENT_ID)
      .setSubject(subject)
      .setIssuedAt(now)
      .setExpirationTime(now + 600)
      .sign(googlePrivate);
  };

  const setupAndIssue = async () => {
    const env = await buildEnv();
    const slug = `inv-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const ws = await issuerApp.request(
      "/v1/workspaces",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ slug, name: "Invite Test", adminEmail: "alice@example.com" }),
      },
      env,
    );
    const created = (await ws.json()) as { workspaceId: string };
    cleanup.push(created.workspaceId);

    const issued = await issuerApp.request(
      "/v1/dev/issue",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          email: "alice@example.com",
          audience: env.ADMIN_AUDIENCE,
        }),
      },
      env,
    );
    const token = ((await issued.json()) as { token: string }).token;

    const mint = await adminApp.request(
      `/v1/workspaces/${created.workspaceId}/invites`,
      {
        method: "POST",
        headers: { "content-type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          email: "vc@example.com",
          scope: { doc_id: "deck" },
          ttl_seconds: 600,
        }),
      },
      env,
    );
    expect(mint.status).toBe(201);
    const minted = (await mint.json()) as { invite_id: string; token: string };
    return { env, workspaceId: created.workspaceId, inviteToken: minted.token };
  };

  it("accepts a valid invite when google email matches", async () => {
    const ctx = await setupAndIssue();
    const idToken = await buildIdToken();
    const res = await issuerApp.request(
      `/v1/workspaces/${ctx.workspaceId}/invites/accept`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          invite_token: ctx.inviteToken,
          google_id_token: idToken,
          cnf_jwk: recipientPubJwk,
        }),
      },
      ctx.env,
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as { capability: string; user_id: string };
    expect(body.capability.split("~").length).toBeGreaterThanOrEqual(2);
    expect(body.user_id).toBeTruthy();
  });

  it("denies when google email does not match the invited email", async () => {
    const ctx = await setupAndIssue();
    const idToken = await buildIdToken({ email: "imposter@example.com" });
    const res = await issuerApp.request(
      `/v1/workspaces/${ctx.workspaceId}/invites/accept`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          invite_token: ctx.inviteToken,
          google_id_token: idToken,
          cnf_jwk: recipientPubJwk,
        }),
      },
      ctx.env,
    );
    expect(res.status).toBe(403);
  });

  it("denies a replay after the invite has been consumed", async () => {
    const ctx = await setupAndIssue();
    const idToken = await buildIdToken();
    const first = await issuerApp.request(
      `/v1/workspaces/${ctx.workspaceId}/invites/accept`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          invite_token: ctx.inviteToken,
          google_id_token: idToken,
          cnf_jwk: recipientPubJwk,
        }),
      },
      ctx.env,
    );
    expect(first.status).toBe(201);
    const replay = await issuerApp.request(
      `/v1/workspaces/${ctx.workspaceId}/invites/accept`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          invite_token: ctx.inviteToken,
          google_id_token: await buildIdToken(),
          cnf_jwk: recipientPubJwk,
        }),
      },
      ctx.env,
    );
    expect(replay.status).toBe(410);
  });

  it("denies an invite token whose signature does not verify", async () => {
    const ctx = await setupAndIssue();
    const parts = ctx.inviteToken.split(".");
    const tampered = `${parts[0]}.${parts[1]}.AAAA`;
    const res = await issuerApp.request(
      `/v1/workspaces/${ctx.workspaceId}/invites/accept`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          invite_token: tampered,
          google_id_token: await buildIdToken(),
          cnf_jwk: recipientPubJwk,
        }),
      },
      ctx.env,
    );
    expect(res.status).toBe(401);
  });

  it("denies when google email is not verified", async () => {
    const ctx = await setupAndIssue();
    const idToken = await buildIdToken({ email_verified: false });
    const res = await issuerApp.request(
      `/v1/workspaces/${ctx.workspaceId}/invites/accept`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          invite_token: ctx.inviteToken,
          google_id_token: idToken,
          cnf_jwk: recipientPubJwk,
        }),
      },
      ctx.env,
    );
    expect(res.status).toBe(403);
  });
});
