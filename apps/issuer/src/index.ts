import type { Email } from "@getpact/core";
import { createClient } from "@getpact/db";
import { rotateStaleKeys } from "@getpact/keystore";
import { createLogger, requestLogger } from "@getpact/logger";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { decodeMek, type Env, isDevIssueEnabled, tokenTtlSeconds } from "./env.js";
import { exchangeGoogleCode } from "./google.js";
import { issueTokenForEmail, redeemRefreshAndIssue } from "./issue.js";
import { buildWorkspaceJwks } from "./jwks.js";
import { createWorkspace } from "./workspace.js";

export const app = new Hono<{ Bindings: Env }>();

const logger = createLogger({ base: { app: "issuer" } });
app.use("*", requestLogger(logger, "issuer"));
app.use("/v1/*", bodyLimit({ maxSize: 32 * 1024 }));

app.get("/health", (c) => c.json({ ok: true }));

app.post("/v1/workspaces", async (c) => {
  const body = await c.req.json<{
    slug: string;
    name: string;
    region?: string;
    adminEmail: string;
    adminName?: string;
  }>();
  const result = await createWorkspace(c.env.DATABASE_URL, decodeMek(c.env), body);
  return c.json(result, 201);
});

app.post("/v1/dev/issue", async (c) => {
  if (!isDevIssueEnabled(c.env)) {
    return c.json({ error: "not_found" }, 404);
  }
  const body = await c.req.json<{ workspaceId: string; email: string; audience: string }>();
  const result = await issueTokenForEmail(c.env.DATABASE_URL, decodeMek(c.env), {
    workspaceId: body.workspaceId,
    email: body.email as Email,
    audience: body.audience,
    ttlSeconds: tokenTtlSeconds(c.env),
    issuerUrl: c.env.ISSUER_BASE_URL,
  });
  return c.json(result);
});

app.post("/v1/oauth/google/exchange", async (c) => {
  const body = await c.req.json<{
    workspaceId: string;
    code: string;
    codeVerifier: string;
    redirectUri: string;
    audience: string;
  }>();

  let identity: Awaited<ReturnType<typeof exchangeGoogleCode>>;
  try {
    identity = await exchangeGoogleCode({
      clientId: c.env.GOOGLE_OAUTH_CLIENT_ID,
      clientSecret: c.env.GOOGLE_OAUTH_CLIENT_SECRET,
      code: body.code,
      codeVerifier: body.codeVerifier,
      redirectUri: body.redirectUri,
      ...(c.env.GOOGLE_TOKEN_ENDPOINT ? { tokenEndpoint: c.env.GOOGLE_TOKEN_ENDPOINT } : {}),
      ...(c.env.GOOGLE_JWKS_URI ? { jwksUri: c.env.GOOGLE_JWKS_URI } : {}),
      ...(c.env.GOOGLE_ISSUER ? { expectedIssuer: c.env.GOOGLE_ISSUER } : {}),
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : "google verification failed";
    return c.json({ error: "invalid_grant", detail: msg }, 401);
  }
  if (!identity.emailVerified) {
    return c.json({ error: "email_not_verified" }, 403);
  }

  try {
    const result = await issueTokenForEmail(c.env.DATABASE_URL, decodeMek(c.env), {
      workspaceId: body.workspaceId,
      email: identity.email as Email,
      audience: body.audience,
      ttlSeconds: tokenTtlSeconds(c.env),
      issuerUrl: c.env.ISSUER_BASE_URL,
    });
    return c.json(result);
  } catch {
    return c.json({ error: "user_not_in_workspace" }, 403);
  }
});

app.post("/v1/refresh", async (c) => {
  const body = await c.req.json<{
    workspaceId: string;
    refreshToken: string;
    audience: string;
  }>();
  const result = await redeemRefreshAndIssue(c.env.DATABASE_URL, decodeMek(c.env), {
    workspaceId: body.workspaceId,
    refreshToken: body.refreshToken,
    audience: body.audience,
    ttlSeconds: tokenTtlSeconds(c.env),
    issuerUrl: c.env.ISSUER_BASE_URL,
  });
  if (!result) return c.json({ error: "invalid_grant" }, 401);
  return c.json(result);
});

app.get("/v1/workspaces/:id/.well-known/jwks.json", async (c) => {
  const id = c.req.param("id");
  const jwks = await buildWorkspaceJwks(c.env.DATABASE_URL, id, "jwt");
  return c.json(jwks, 200, { "cache-control": "public, max-age=300" });
});

app.get("/v1/workspaces/:id/.well-known/audit-jwks.json", async (c) => {
  const id = c.req.param("id");
  const jwks = await buildWorkspaceJwks(c.env.DATABASE_URL, id, "audit");
  return c.json(jwks, 200, { "cache-control": "public, max-age=300" });
});

const JWT_KEY_MAX_AGE_SECONDS = 90 * 24 * 60 * 60;
const AUDIT_KEY_MAX_AGE_SECONDS = 180 * 24 * 60 * 60;
const VERIFICATION_GRACE_SECONDS = 7 * 24 * 60 * 60;

export const rotateAllStale = async (
  env: Env,
): Promise<{
  jwt: { rotated: number; errors: number };
  audit: { rotated: number; errors: number };
}> => {
  const rawMek = decodeMek(env);
  const db = createClient(env.DATABASE_URL);
  const jwt = await rotateStaleKeys(
    db,
    rawMek,
    "jwt",
    JWT_KEY_MAX_AGE_SECONDS,
    VERIFICATION_GRACE_SECONDS,
  );
  const audit = await rotateStaleKeys(
    db,
    rawMek,
    "audit",
    AUDIT_KEY_MAX_AGE_SECONDS,
    VERIFICATION_GRACE_SECONDS,
  );
  return { jwt, audit };
};

export default app;
