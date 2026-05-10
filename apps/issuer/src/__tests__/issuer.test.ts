import { exportAesKey, generateAesKey, toBase64, verifyJwt } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { listVerifyingKeys } from "@getpact/keystore";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import app from "../index.js";

const url = process.env.RLS_TEST_DB;
const adminUrl = process.env.DATABASE_URL ?? url;
const run = url && adminUrl ? describe : describe.skip;

const buildEnv = async () => {
  const mek = await generateAesKey();
  const rawMek = await exportAesKey(mek);
  return {
    DATABASE_URL: adminUrl as string,
    MEK: toBase64(rawMek),
    GOOGLE_OAUTH_CLIENT_ID: "test",
    GOOGLE_OAUTH_CLIENT_SECRET: "test",
    ISSUER_BASE_URL: "https://issuer.test/acme",
  };
};

run("issuer end-to-end", () => {
  const cleanup: string[] = [];
  const adminDb = createClient(adminUrl as string);

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

  it("creates workspace and issues a verifiable jwt", async () => {
    const env = await buildEnv();
    const slug = `iss-${Date.now()}`;

    const createRes = await app.request(
      "/v1/workspaces",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          slug,
          name: "Issuer Test",
          adminEmail: "alice@example.com",
        }),
      },
      env,
    );
    expect(createRes.status).toBe(201);
    const created = (await createRes.json()) as {
      workspaceId: string;
      adminUserId: string;
      jwtKeyId: string;
      auditKeyId: string;
    };
    cleanup.push(created.workspaceId);
    expect(created.jwtKeyId).toBeDefined();
    expect(created.auditKeyId).toBeDefined();

    const issueRes = await app.request(
      "/v1/dev/issue",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          email: "alice@example.com",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(issueRes.status).toBe(200);
    const issued = (await issueRes.json()) as {
      token: string;
      jti: string;
      exp: number;
    };
    expect(issued.token.split(".").length).toBe(3);

    const verifying = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      listVerifyingKeys(tx, created.workspaceId, "jwt"),
    );
    expect(verifying.length).toBe(1);
    const publicKey = verifying[0]?.publicKey;
    if (!publicKey) throw new Error("missing public key");

    const result = await verifyJwt(issued.token, {
      publicKey,
      issuer: env.ISSUER_BASE_URL,
      audience: "pact-mcp",
    });
    expect(result.payload.sub).toBe(created.adminUserId);
    expect(result.payload.email).toBe("alice@example.com");
    expect(result.payload.scopes).toEqual(["admin"]);
  });

  it("publishes a workspace JWKS with the active signing key", async () => {
    const env = await buildEnv();
    const slug = `iss-jwks-${Date.now()}`;

    const createRes = await app.request(
      "/v1/workspaces",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          slug,
          name: "JWKS Test",
          adminEmail: "admin@example.com",
        }),
      },
      env,
    );
    const created = (await createRes.json()) as { workspaceId: string; jwtKeyId: string };
    cleanup.push(created.workspaceId);

    const jwksRes = await app.request(
      `/v1/workspaces/${created.workspaceId}/.well-known/jwks.json`,
      undefined,
      env,
    );
    expect(jwksRes.status).toBe(200);
    const jwks = (await jwksRes.json()) as {
      keys: Array<{ kty: string; crv: string; x: string; kid: string; alg: string; use: string }>;
    };
    expect(jwks.keys.length).toBe(1);
    const key = jwks.keys[0];
    expect(key?.kty).toBe("OKP");
    expect(key?.crv).toBe("Ed25519");
    expect(key?.alg).toBe("EdDSA");
    expect(key?.kid).toBe(created.jwtKeyId);
    expect(key?.x).toBeDefined();
  });

  it("rotates refresh token on each redeem and rejects reuse", async () => {
    const env = await buildEnv();
    const slug = `iss-rt-${Date.now()}`;
    const createRes = await app.request(
      "/v1/workspaces",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ slug, name: "Rt", adminEmail: "alice@example.com" }),
      },
      env,
    );
    const created = (await createRes.json()) as { workspaceId: string };
    cleanup.push(created.workspaceId);

    const issueRes = await app.request(
      "/v1/dev/issue",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          email: "alice@example.com",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    const issued = (await issueRes.json()) as { token: string; refreshToken: string };
    expect(issued.refreshToken.length).toBeGreaterThan(20);

    const refreshRes = await app.request(
      "/v1/refresh",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          refreshToken: issued.refreshToken,
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(refreshRes.status).toBe(200);
    const rotated = (await refreshRes.json()) as { token: string; refreshToken: string };
    expect(rotated.refreshToken).not.toBe(issued.refreshToken);
    expect(rotated.token).not.toBe(issued.token);

    const reuseRes = await app.request(
      "/v1/refresh",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          refreshToken: issued.refreshToken,
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(reuseRes.status).toBe(401);
  });

  it("rejects refresh with bogus token", async () => {
    const env = await buildEnv();
    const slug = `iss-rtb-${Date.now()}`;
    const createRes = await app.request(
      "/v1/workspaces",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ slug, name: "Rtb", adminEmail: "admin@example.com" }),
      },
      env,
    );
    const created = (await createRes.json()) as { workspaceId: string };
    cleanup.push(created.workspaceId);
    const res = await app.request(
      "/v1/refresh",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          refreshToken: "not-a-real-refresh",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(res.status).toBe(401);
  });

  it("rejects issue for unknown email", async () => {
    const env = await buildEnv();
    const slug = `iss-err-${Date.now()}`;
    const createRes = await app.request(
      "/v1/workspaces",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ slug, name: "Err", adminEmail: "admin@example.com" }),
      },
      env,
    );
    const created = (await createRes.json()) as { workspaceId: string };
    cleanup.push(created.workspaceId);

    const issueRes = await app.request(
      "/v1/dev/issue",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          email: "ghost@example.com",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(issueRes.status).toBeGreaterThanOrEqual(400);
  });
});
