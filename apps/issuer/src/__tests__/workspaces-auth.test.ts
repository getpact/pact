import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { exportAesKey, generateAesKey, toBase64 } from "@getpact/crypto";
import { createClient } from "@getpact/db";
import { roles, userRoles, users, workspaces } from "@getpact/db/schema";
import { and, eq } from "drizzle-orm";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import app from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const CLIENT_ID = "test-client-id";

run("workspace creation auth gate", () => {
  const adminDb = createClient(url as string);
  const cleanup: string[] = [];

  let googlePrivate: CryptoKey;
  let googleJwk: Awaited<ReturnType<typeof exportJWK>>;
  const kid = "mock-google-key-ws";

  let server: ReturnType<typeof createServer>;
  let baseUrl: string;
  let issuerHost: string;

  beforeAll(async () => {
    const pair = await generateKeyPair("RS256", { extractable: true });
    googlePrivate = pair.privateKey as CryptoKey;
    googleJwk = await exportJWK(pair.publicKey as CryptoKey);
    googleJwk.kid = kid;
    googleJwk.alg = "RS256";
    googleJwk.use = "sig";

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
    issuerHost = baseUrl;
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
      } catch {
        // ignore
      }
    }
  });

  const buildEnv = async (
    overrides: Record<string, string | undefined> = {},
  ): Promise<Record<string, string>> => {
    const mek = await generateAesKey();
    const env: Record<string, string> = {
      DATABASE_URL: url as string,
      MEK: toBase64(await exportAesKey(mek)),
      GOOGLE_OAUTH_CLIENT_ID: CLIENT_ID,
      GOOGLE_OAUTH_CLIENT_SECRET: "test-secret",
      GOOGLE_JWKS_URI: `${baseUrl}/jwks`,
      GOOGLE_ISSUER: issuerHost,
      ISSUER_BASE_URL: "https://issuer.test/acme",
      ENVIRONMENT: "test",
    };
    for (const [k, v] of Object.entries(overrides)) {
      if (v === undefined) delete env[k];
      else env[k] = v;
    }
    return env;
  };

  const buildIdToken = async (
    overrides: Record<string, unknown> = {},
    subject = "google-sub-ws-admin",
  ): Promise<string> => {
    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
      email: "founder@example.com",
      email_verified: true,
      hd: "example.com",
    };
    Object.assign(claims, overrides);
    if (claims.hd === undefined) delete claims.hd;
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid })
      .setIssuer(issuerHost)
      .setAudience(CLIENT_ID)
      .setSubject(subject)
      .setIssuedAt(now)
      .setExpirationTime(now + 600)
      .sign(googlePrivate);
  };

  const uniqueSlug = (prefix: string): string =>
    `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

  const post = (env: Record<string, unknown>, body: Record<string, unknown>) =>
    app.request(
      "/v1/workspaces",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      },
      env,
    );

  it("rejects unauthenticated creation when flag is off", async () => {
    const env = await buildEnv();
    const res = await post(env, {
      slug: uniqueSlug("auth-off"),
      name: "Auth Off",
      adminEmail: "founder@example.com",
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("unauthorized");
  });

  it("allows unauthenticated creation when flag is on outside production", async () => {
    const env = await buildEnv({ PACT_ALLOW_UNAUTHED_WORKSPACE_CREATE: "true" });
    const res = await post(env, {
      slug: uniqueSlug("auth-flag"),
      name: "Auth Flag",
      adminEmail: "founder@example.com",
    });
    expect(res.status).toBe(201);
    const created = (await res.json()) as { workspaceId: string; adminUserId: string };
    cleanup.push(created.workspaceId);
    expect(created.adminUserId).toBeDefined();
  });

  it.skipIf(!process.env.RLS_TEST_DB)("ignores the unauth flag in production", async () => {
    const env = await buildEnv({
      ENVIRONMENT: "production",
      PACT_ALLOW_UNAUTHED_WORKSPACE_CREATE: "true",
      DATABASE_URL: process.env.RLS_TEST_DB,
    });
    const res = await post(env, {
      slug: uniqueSlug("auth-prod"),
      name: "Auth Prod",
      adminEmail: "founder@example.com",
    });
    expect(res.status).toBe(401);
  });

  it("creates a workspace when a valid google id token is presented", async () => {
    const env = await buildEnv();
    const idToken = await buildIdToken();
    const slug = uniqueSlug("auth-on");
    const res = await post(env, {
      slug,
      name: "Auth On",
      adminEmail: "founder@example.com",
      google_id_token: idToken,
    });
    expect(res.status).toBe(201);
    const created = (await res.json()) as {
      workspaceId: string;
      adminUserId: string;
    };
    cleanup.push(created.workspaceId);

    const admins = await adminDb
      .select({ id: users.id, email: users.email })
      .from(users)
      .where(
        and(eq(users.workspaceId, created.workspaceId), eq(users.email, "founder@example.com")),
      )
      .limit(1);
    expect(admins[0]?.id).toBe(created.adminUserId);

    const adminRoles = await adminDb
      .select({ name: roles.name })
      .from(roles)
      .innerJoin(userRoles, eq(userRoles.roleId, roles.id))
      .where(
        and(eq(roles.workspaceId, created.workspaceId), eq(userRoles.userId, admins[0]?.id ?? "")),
      );
    expect(adminRoles.map((r) => r.name)).toContain("admin");
  });

  it("rejects when google email is not verified", async () => {
    const env = await buildEnv();
    const idToken = await buildIdToken({ email_verified: false });
    const res = await post(env, {
      slug: uniqueSlug("auth-unverified"),
      name: "Unverified",
      adminEmail: "founder@example.com",
      google_id_token: idToken,
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("email_not_verified");
  });

  it("rejects when adminEmail does not match the verified google identity", async () => {
    const env = await buildEnv();
    const idToken = await buildIdToken();
    const res = await post(env, {
      slug: uniqueSlug("auth-mismatch"),
      name: "Mismatch",
      adminEmail: "someone-else@example.com",
      google_id_token: idToken,
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("admin_email_mismatch");
  });

  it("rejects when the google id token signature is invalid", async () => {
    const env = await buildEnv();
    const res = await post(env, {
      slug: uniqueSlug("auth-bad-sig"),
      name: "Bad Sig",
      adminEmail: "founder@example.com",
      google_id_token: "not.a.real.token",
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("google_identity_verification_failed");
  });
});
