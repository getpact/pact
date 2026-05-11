import {
  AuthzError,
  type Email,
  isStrongSharedSecret,
  isUuid,
  PactError,
  securityHeaders,
  timingSafeEqualString,
} from "@getpact/core";
import { assertSafeRuntimeDbRole, createClient, UnsafeRuntimeDbRoleError } from "@getpact/db";
import { rotateStaleKeys } from "@getpact/keystore";
import { createLogger, requestLogger } from "@getpact/logger";
import {
  databaseRateLimiter,
  memoryRateLimiter,
  type RateLimiter,
  rateLimit,
  sweepExpiredRateBuckets,
} from "@getpact/ratelimit";
import { type Context, Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { decodeMek, type Env, isDevIssueEnabled, tokenTtlSeconds } from "./env.js";
import { exchangeGoogleCode } from "./google.js";
import { issueTokenBundleForEmail, issueTokenForEmail, redeemRefreshAndIssue } from "./issue.js";
import { buildWorkspaceJwks } from "./jwks.js";
import { createWorkspace } from "./workspace.js";

export const app = new Hono<{ Bindings: Env }>();

const logger = createLogger({ base: { app: "issuer" } });
app.use("*", requestLogger(logger, "issuer"));
app.use("*", async (c, next) => {
  await next();
  const headers = securityHeaders({ production: c.env.ENVIRONMENT === "production" });
  for (const [k, v] of Object.entries(headers)) c.header(k, v);
});
app.use("/v1/*", bodyLimit({ maxSize: 32 * 1024 }));
app.use("/v1/*", async (c, next) => {
  if (c.env.ENVIRONMENT === "production" && new URL(c.req.url).pathname === "/v1/dev/issue") {
    await next();
    return;
  }
  try {
    await assertSafeRuntimeDbRole(c.env.DATABASE_URL, {
      production: c.env.ENVIRONMENT === "production",
    });
  } catch (e) {
    if (e instanceof UnsafeRuntimeDbRoleError) {
      return c.json({ error: "misconfigured", message: "unsafe runtime database role" }, 503);
    }
    throw e;
  }
  await next();
});

const memLimiter = memoryRateLimiter();
const testLimiter: RateLimiter = {
  async hit(_key, limit) {
    return { allowed: true, remaining: limit, resetAt: Date.now() + 60_000 };
  },
};
const limiter = (env: Env): RateLimiter =>
  env.ENVIRONMENT === "production"
    ? databaseRateLimiter(env.DATABASE_URL)
    : env.ENVIRONMENT === "test"
      ? testLimiter
      : memLimiter;
const rateLimitKey =
  (env: Env, route: string) =>
  (c: Context): string => {
    const client =
      c.req.header("cf-connecting-ip") ??
      (env.ENVIRONMENT === "production"
        ? undefined
        : c.req.header("x-forwarded-for")?.split(",")[0]?.trim()) ??
      "anonymous";
    return `${route}:${client}`;
  };

app.use("/v1/refresh", (c, next) =>
  rateLimit({
    limiter: limiter(c.env),
    limit: 30,
    windowSeconds: 60,
    keyFn: rateLimitKey(c.env, "refresh"),
  })(c, next),
);
app.use("/v1/oauth/google/exchange", (c, next) =>
  rateLimit({
    limiter: limiter(c.env),
    limit: 10,
    windowSeconds: 60,
    keyFn: rateLimitKey(c.env, "oauth-google-exchange"),
  })(c, next),
);
app.use("/v1/workspaces", (c, next) =>
  rateLimit({
    limiter: limiter(c.env),
    limit: 5,
    windowSeconds: 60,
    keyFn: rateLimitKey(c.env, "workspaces"),
  })(c, next),
);
app.use("/v1/dev/issue", (c, next) =>
  rateLimit({
    limiter: limiter(c.env),
    limit: 30,
    windowSeconds: 60,
    keyFn: rateLimitKey(c.env, "dev-issue"),
  })(c, next),
);

app.get("/health", (c) => c.json({ ok: true }));

const enforceRouteRateLimit = async (
  c: Context<{ Bindings: Env }>,
  input: { key: string; limit: number; windowSeconds: number },
): Promise<Response | null> => {
  const result = await limiter(c.env).hit(input.key, input.limit, input.windowSeconds);
  c.header("x-ratelimit-limit", String(input.limit));
  c.header("x-ratelimit-remaining", String(result.remaining));
  c.header("x-ratelimit-reset", String(Math.ceil(result.resetAt / 1000)));
  if (result.allowed) return null;
  const retryAfter = Math.max(Math.ceil((result.resetAt - Date.now()) / 1000), 1);
  c.header("retry-after", String(retryAfter));
  return c.json({ error: "rate_limited" }, 429);
};

app.post("/v1/workspaces", async (c) => {
  const body = await c.req.json<{
    slug: string;
    name: string;
    region?: string;
    adminEmail: string;
    adminName?: string;
  }>();
  try {
    const result = await createWorkspace(c.env.DATABASE_URL, decodeMek(c.env), body);
    return c.json(result, 201);
  } catch (e) {
    if (e instanceof PactError) {
      return c.json({ error: e.code, message: e.message }, e.status as 400 | 409);
    }
    throw e;
  }
});

app.post("/v1/dev/issue", async (c) => {
  if (!isDevIssueEnabled(c.env)) {
    return c.json({ error: "not_found" }, 404);
  }
  if (c.env.ENVIRONMENT !== "test") {
    if (!c.env.DEV_ISSUE_SECRET) return c.json({ error: "not_found" }, 404);
    if (!isStrongSharedSecret(c.env.DEV_ISSUE_SECRET)) {
      return c.json({ error: "misconfigured", message: "dev issue secret is too weak" }, 503);
    }
    const received = c.req.header("x-pact-dev-issue-secret") ?? "";
    if (!timingSafeEqualString(received, c.env.DEV_ISSUE_SECRET)) {
      return c.json({ error: "unauthorized", message: "invalid dev issue secret" }, 401);
    }
  }
  const body = await c.req.json<{ workspaceId: string; email: string; audience: string }>();
  try {
    const result = await issueTokenForEmail(c.env.DATABASE_URL, decodeMek(c.env), {
      workspaceId: body.workspaceId,
      email: body.email as Email,
      audience: body.audience,
      ttlSeconds: tokenTtlSeconds(c.env),
      issuerUrl: c.env.ISSUER_BASE_URL,
    });
    return c.json(result);
  } catch (e) {
    if (e instanceof PactError) {
      return c.json({ error: e.code, message: e.message }, e.status as 400);
    }
    throw e;
  }
});

app.post("/v1/oauth/google/exchange", async (c) => {
  const body = await c.req.json<{
    workspaceId: string;
    code: string;
    codeVerifier: string;
    redirectUri: string;
    audience: string;
  }>();
  if (!isUuid(body.workspaceId)) {
    return c.json({ error: "invalid_workspace" }, 400);
  }
  if (body.audience === "pact-admin" || body.audience === "pact-audit") {
    return c.json({ error: "invalid_audience" }, 400);
  }

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
  } catch {
    return c.json({ error: "invalid_grant" }, 401);
  }
  if (!identity.emailVerified) {
    return c.json({ error: "email_not_verified" }, 403);
  }

  try {
    const result = await issueTokenForEmail(c.env.DATABASE_URL, decodeMek(c.env), {
      workspaceId: body.workspaceId,
      email: identity.email as Email,
      googleSub: identity.sub,
      audience: body.audience,
      ttlSeconds: tokenTtlSeconds(c.env),
      issuerUrl: c.env.ISSUER_BASE_URL,
    });
    return c.json(result);
  } catch (e) {
    if (e instanceof AuthzError) {
      return c.json({ error: "user_not_in_workspace" }, 403);
    }
    if (e instanceof PactError) {
      return c.json({ error: e.code, message: e.message }, e.status as 400);
    }
    return c.json({ error: "user_not_in_workspace" }, 403);
  }
});

app.post("/v1/oauth/google/session", async (c) => {
  const serviceToken = c.env.WEB_ISSUER_SERVICE_TOKEN;
  if (!serviceToken || !isStrongSharedSecret(serviceToken)) {
    return c.json({ error: "misconfigured", message: "web issuer service token is missing" }, 503);
  }
  const received = c.req.header("x-pact-web-service-token") ?? "";
  if (!timingSafeEqualString(received, serviceToken)) {
    return c.json({ error: "unauthorized", message: "invalid service token" }, 401);
  }
  const body = await c.req.json<{
    workspaceId: string;
    code: string;
    codeVerifier: string;
    redirectUri: string;
    audiences: string[];
  }>();
  if (!isUuid(body.workspaceId)) {
    return c.json({ error: "invalid_workspace" }, 400);
  }
  const limited = await enforceRouteRateLimit(c, {
    key: `oauth-google-session:${body.workspaceId}`,
    limit: 10,
    windowSeconds: 60,
  });
  if (limited) return limited;
  if (!c.env.WEB_OAUTH_REDIRECT_URI || body.redirectUri !== c.env.WEB_OAUTH_REDIRECT_URI) {
    return c.json({ error: "invalid_redirect_uri" }, 400);
  }
  const audiences = [...new Set(body.audiences ?? [])];
  const allowedDashboardAudiences = new Set(["pact-admin", "pact-audit"]);
  if (audiences.length === 0 || audiences.some((aud) => !allowedDashboardAudiences.has(aud))) {
    return c.json({ error: "invalid_audience" }, 400);
  }

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
  } catch {
    return c.json({ error: "invalid_grant" }, 401);
  }
  if (!identity.emailVerified) {
    return c.json({ error: "email_not_verified" }, 403);
  }

  try {
    const tokens = await issueTokenBundleForEmail(c.env.DATABASE_URL, decodeMek(c.env), {
      workspaceId: body.workspaceId,
      email: identity.email as Email,
      googleSub: identity.sub,
      audiences,
      ttlSeconds: tokenTtlSeconds(c.env),
      issuerUrl: c.env.ISSUER_BASE_URL,
    });
    return c.json({ tokens });
  } catch (e) {
    if (e instanceof AuthzError) {
      return c.json({ error: "user_not_in_workspace" }, 403);
    }
    if (e instanceof PactError) {
      return c.json({ error: e.code, message: e.message }, e.status as 400);
    }
    return c.json({ error: "user_not_in_workspace" }, 403);
  }
});

app.post("/v1/refresh", async (c) => {
  const body = await c.req.json<{
    workspaceId: string;
    refreshToken: string;
    audience: string;
  }>();
  try {
    const result = await redeemRefreshAndIssue(c.env.DATABASE_URL, decodeMek(c.env), {
      workspaceId: body.workspaceId,
      refreshToken: body.refreshToken,
      audience: body.audience,
      ttlSeconds: tokenTtlSeconds(c.env),
      issuerUrl: c.env.ISSUER_BASE_URL,
    });
    if (!result) return c.json({ error: "invalid_grant" }, 401);
    return c.json(result);
  } catch (e) {
    if (e instanceof PactError) {
      return c.json({ error: e.code, message: e.message }, e.status as 400);
    }
    throw e;
  }
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
  rateBucketsSwept: number;
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
  const rateBucketsSwept = await sweepExpiredRateBuckets(db);
  return { jwt, audit, rateBucketsSwept };
};

export default app;
