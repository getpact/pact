import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { exportAesKey, generateAesKey, toBase64 } from "@getpact/crypto";
import { createClient } from "@getpact/db";
import { auditEvents, users, workspaces } from "@getpact/db/schema";
import { and, eq } from "drizzle-orm";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import app from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const CLIENT_ID = "test-client-id";

run("google oidc exchange", () => {
  const adminDb = createClient(url as string);
  const cleanup: string[] = [];

  let googlePrivate: CryptoKey;
  let googleJwk: Awaited<ReturnType<typeof exportJWK>>;
  const kid = "mock-google-key-1";

  let server: ReturnType<typeof createServer>;
  let baseUrl: string;
  let issuerHost: string;
  let nextIdToken: string | null = null;
  let nextTokenStatus = 200;
  let nextTokenBody: unknown = { error: "invalid_grant" };

  beforeAll(async () => {
    const pair = await generateKeyPair("RS256", { extractable: true });
    googlePrivate = pair.privateKey as CryptoKey;
    googleJwk = await exportJWK(pair.publicKey as CryptoKey);
    googleJwk.kid = kid;
    googleJwk.alg = "RS256";
    googleJwk.use = "sig";

    server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const path = req.url ?? "";
      if (path === "/token" && req.method === "POST") {
        req.on("data", () => {});
        req.on("end", () => {
          if (nextTokenStatus !== 200) {
            res.writeHead(nextTokenStatus, { "content-type": "application/json" });
            res.end(JSON.stringify(nextTokenBody));
            return;
          }
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ id_token: nextIdToken }));
        });
        return;
      }
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
    nextIdToken = null;
    nextTokenStatus = 200;
    nextTokenBody = { error: "invalid_grant" };
  });

  const buildIdToken = async (
    overrides: Record<string, unknown> = {},
    subject = "google-sub-123",
  ): Promise<string> => {
    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
      email: "alice@example.com",
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

  const buildEnv = async () => {
    const mek = await generateAesKey();
    return {
      DATABASE_URL: url as string,
      MEK: toBase64(await exportAesKey(mek)),
      GOOGLE_OAUTH_CLIENT_ID: CLIENT_ID,
      GOOGLE_OAUTH_CLIENT_SECRET: "test-secret",
      GOOGLE_TOKEN_ENDPOINT: `${baseUrl}/token`,
      GOOGLE_JWKS_URI: `${baseUrl}/jwks`,
      GOOGLE_ISSUER: issuerHost,
      ISSUER_BASE_URL: "https://issuer.test/acme",
      ENVIRONMENT: "test",
      WEB_ISSUER_SERVICE_TOKEN: "test-web-issuer-service-token-12345",
      WEB_OAUTH_REDIRECT_URI: "https://app.test/v1/auth/google/callback",
    };
  };

  const setupWorkspace = async (
    env: Awaited<ReturnType<typeof buildEnv>>,
    adminEmail = "alice@example.com",
  ) => {
    const slug = `g-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const res = await app.request(
      "/v1/workspaces",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          slug,
          name: "Google Test",
          adminEmail,
        }),
      },
      env,
    );
    const created = (await res.json()) as { workspaceId: string };
    cleanup.push(created.workspaceId);
    return created;
  };

  it("exchanges a valid google code and issues a Pact JWT", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);
    nextIdToken = await buildIdToken();

    const res = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "real-google-auth-code",
          codeVerifier: `v${"x".repeat(43)}`,
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { token: string; refreshToken: string };
    expect(body.token.split(".").length).toBe(3);
    expect(body.refreshToken.length).toBeGreaterThan(20);
  });

  it("exchanges one google code for a dashboard token bundle", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);
    nextIdToken = await buildIdToken();

    const res = await app.request(
      "/v1/oauth/google/session",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-pact-web-service-token": env.WEB_ISSUER_SERVICE_TOKEN,
        },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "real-google-auth-code",
          codeVerifier: `v${"x".repeat(43)}`,
          redirectUri: "https://app.test/v1/auth/google/callback",
          audiences: ["pact-admin", "pact-audit"],
        }),
      },
      env,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("x-ratelimit-limit")).toBe("10");
    const body = (await res.json()) as {
      tokens: Record<string, { token: string; refreshToken: string }>;
    };
    expect(body.tokens["pact-admin"]?.token.split(".").length).toBe(3);
    expect(body.tokens["pact-audit"]?.token.split(".").length).toBe(3);
    expect(body.tokens["pact-admin"]?.refreshToken).not.toBe(
      body.tokens["pact-audit"]?.refreshToken,
    );
  });

  it("rejects a changed Google subject for an already linked email", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);
    nextIdToken = await buildIdToken({}, "google-sub-123");

    const first = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code-1",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(first.status).toBe(200);

    nextIdToken = await buildIdToken({}, "different-google-sub");
    const second = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code-2",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(second.status).toBe(403);
  });

  it("backfills google subject for a pre-existing workspace user", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);
    nextIdToken = await buildIdToken({}, "google-sub-backfill");

    const before = await adminDb
      .select({ googleSub: users.googleSub })
      .from(users)
      .where(and(eq(users.workspaceId, created.workspaceId), eq(users.email, "alice@example.com")))
      .limit(1);
    expect(before[0]?.googleSub).toBeNull();

    const res = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code-backfill",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(res.status).toBe(200);

    const after = await adminDb
      .select({ googleSub: users.googleSub })
      .from(users)
      .where(and(eq(users.workspaceId, created.workspaceId), eq(users.email, "alice@example.com")))
      .limit(1);
    expect(after[0]?.googleSub).toBe("google-sub-backfill");
  });

  it("revokes existing refresh tokens when google subject is first bound", async () => {
    const env = { ...(await buildEnv()), ENABLE_DEV_ISSUE: "true" };
    const created = await setupWorkspace(env);

    const issueBeforeBinding = await app.request(
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
    expect(issueBeforeBinding.status).toBe(200);
    const issued = (await issueBeforeBinding.json()) as { refreshToken: string };

    nextIdToken = await buildIdToken({}, "google-sub-revokes-refresh");
    const bind = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code-bind-revoke",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(bind.status).toBe(200);

    const refresh = await app.request(
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
    expect(refresh.status).toBe(401);
  });

  it.skipIf(!process.env.RLS_TEST_DB)(
    "backfills google subject using the runtime RLS role",
    async () => {
      const env = await buildEnv();
      const created = await setupWorkspace(env);
      nextIdToken = await buildIdToken({}, "google-sub-rls");

      const res = await app.request(
        "/v1/oauth/google/session",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-pact-web-service-token": env.WEB_ISSUER_SERVICE_TOKEN,
          },
          body: JSON.stringify({
            workspaceId: created.workspaceId,
            code: "code-rls",
            codeVerifier: "v".repeat(43),
            redirectUri: env.WEB_OAUTH_REDIRECT_URI,
            audiences: ["pact-admin", "pact-audit"],
          }),
        },
        { ...env, DATABASE_URL: process.env.RLS_TEST_DB },
      );
      expect(res.status).toBe(200);

      const rows = await adminDb
        .select({ googleSub: users.googleSub })
        .from(users)
        .where(
          and(eq(users.workspaceId, created.workspaceId), eq(users.email, "alice@example.com")),
        )
        .limit(1);
      expect(rows[0]?.googleSub).toBe("google-sub-rls");
    },
  );

  it("rejects google subject collision when current email belongs to another user", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);
    await adminDb.insert(users).values({
      workspaceId: created.workspaceId,
      email: "bob@example.com",
      googleSub: "google-sub-123",
    });
    nextIdToken = await buildIdToken({}, "google-sub-123");

    const res = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code-collision",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("google_identity_mismatch");
    const rows = await adminDb
      .select({ email: users.email, googleSub: users.googleSub })
      .from(users)
      .where(eq(users.workspaceId, created.workspaceId));
    expect(rows.find((row) => row.email === "alice@example.com")?.googleSub).toBeNull();
    expect(rows.find((row) => row.email === "bob@example.com")?.googleSub).toBe("google-sub-123");
    const audits = await adminDb
      .select({
        action: auditEvents.action,
        decision: auditEvents.decision,
        supporting: auditEvents.supporting,
      })
      .from(auditEvents)
      .where(eq(auditEvents.workspaceId, created.workspaceId));
    expect(audits).toContainEqual(
      expect.objectContaining({
        action: "issuer.google_auth.denied",
        decision: "deny",
        supporting: expect.objectContaining({
          reason: "google_identity_mismatch",
          email: "alice@example.com",
        }),
      }),
    );
  });

  it("allows the same google subject in different workspaces", async () => {
    const env = await buildEnv();
    const firstWorkspace = await setupWorkspace(env);
    const secondWorkspace = await setupWorkspace(env);

    nextIdToken = await buildIdToken({}, "google-sub-cross-workspace");
    const first = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: firstWorkspace.workspaceId,
          code: "code-first",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(first.status).toBe(200);

    nextIdToken = await buildIdToken({}, "google-sub-cross-workspace");
    const second = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: secondWorkspace.workspaceId,
          code: "code-second",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(second.status).toBe(200);
  });

  it("uses bound google subject as the stable login key after email changes", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);
    nextIdToken = await buildIdToken({}, "google-sub-stable");

    const first = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code-stable-first",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(first.status).toBe(200);

    nextIdToken = await buildIdToken(
      { email: "alice.renamed@example.com", hd: "example.com" },
      "google-sub-stable",
    );
    const second = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code-stable-second",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(second.status).toBe(200);
  });

  it("rejects first binding for non-authoritative non-gmail email", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);
    nextIdToken = await buildIdToken({ hd: undefined }, "google-sub-no-hd");

    const res = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code-no-hd",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("google_email_not_authoritative");
  });

  it("accepts first binding for gmail addresses without hosted domain", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env, "alice@gmail.com");
    nextIdToken = await buildIdToken(
      { email: "alice@gmail.com", hd: undefined },
      "google-sub-gmail",
    );

    const res = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code-gmail",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(res.status).toBe(200);
  });

  it("rejects first binding for googlemail.com without hosted domain", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env, "alice@googlemail.com");
    nextIdToken = await buildIdToken(
      { email: "alice@googlemail.com", hd: undefined },
      "google-sub-googlemail",
    );

    const res = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code-googlemail",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(res.status).toBe(403);
  });

  it("accepts first binding for Google Workspace aliases with hosted domain", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env, "cto@acme.io");
    nextIdToken = await buildIdToken({ email: "cto@acme.io", hd: "acme.com" }, "google-sub-alias");

    const res = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code-alias",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(res.status).toBe(200);
  });

  it("rejects dashboard token bundle requests with unsupported audiences", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);

    const res = await app.request(
      "/v1/oauth/google/session",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-pact-web-service-token": env.WEB_ISSUER_SERVICE_TOKEN,
        },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://app.test/v1/auth/google/callback",
          audiences: ["pact-admin", "pact-gateway"],
        }),
      },
      env,
    );
    expect(res.status).toBe(400);
  });

  it("rejects generic Google exchange for dashboard audiences", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);

    const res = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-admin",
        }),
      },
      env,
    );
    expect(res.status).toBe(400);
  });

  it("rejects dashboard token bundle requests without service auth", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);

    const res = await app.request(
      "/v1/oauth/google/session",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code",
          codeVerifier: "v".repeat(43),
          redirectUri: env.WEB_OAUTH_REDIRECT_URI,
          audiences: ["pact-admin", "pact-audit"],
        }),
      },
      env,
    );
    expect(res.status).toBe(401);
  });

  it("rejects dashboard token bundle requests with the wrong redirect URI", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);

    const res = await app.request(
      "/v1/oauth/google/session",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-pact-web-service-token": env.WEB_ISSUER_SERVICE_TOKEN,
        },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://evil.test/callback",
          audiences: ["pact-admin", "pact-audit"],
        }),
      },
      env,
    );
    expect(res.status).toBe(400);
  });

  it("rejects when google email is unverified", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);
    nextIdToken = await buildIdToken({ email_verified: false });

    const res = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("email_not_verified");
  });

  it("rejects user not in workspace", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);
    nextIdToken = await buildIdToken({ email: "stranger@example.com" });

    const res = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "code",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("user_not_in_workspace");
  });

  it("returns upstream failure when Google token endpoint errors", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);
    nextTokenStatus = 500;
    nextTokenBody = { error: "server_error" };

    const res = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "bad-code",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(res.status).toBe(502);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("google_oauth_exchange_failed");
  });

  it("returns upstream failure when Google token response has no id token", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);
    nextIdToken = null;

    const res = await app.request(
      "/v1/oauth/google/session",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-pact-web-service-token": env.WEB_ISSUER_SERVICE_TOKEN,
        },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "bad-code",
          codeVerifier: "v".repeat(43),
          redirectUri: env.WEB_OAUTH_REDIRECT_URI,
          audiences: ["pact-admin", "pact-audit"],
        }),
      },
      env,
    );
    expect(res.status).toBe(502);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("google_identity_verification_failed");
  });

  it("rejects when google token endpoint fails", async () => {
    const env = await buildEnv();
    const created = await setupWorkspace(env);
    nextTokenStatus = 400;
    nextTokenBody = { error: "invalid_grant", client_secret: env.GOOGLE_OAUTH_CLIENT_SECRET };

    const res = await app.request(
      "/v1/oauth/google/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          code: "bad-code",
          codeVerifier: "v".repeat(43),
          redirectUri: "https://localhost:8787/callback",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(res.status).toBe(401);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({ error: "invalid_grant" });
  });
});
