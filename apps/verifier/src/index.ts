import { isStrongSharedSecret, securityHeaders, timingSafeEqualString } from "@getpact/core";
import { fromBase64 } from "@getpact/crypto";
import { assertSafeRuntimeDbRole, UnsafeRuntimeDbRoleError } from "@getpact/db";
import { createLogger, requestLogger } from "@getpact/logger";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { type KVNamespace, kvRevocationCache } from "./cache.js";
import { AuditUnavailableError, verifyAction } from "./verify.js";

type Env = {
  DATABASE_URL: string;
  MEK: string;
  ISSUER_BASE_URL: string;
  ENVIRONMENT?: string;
  VERIFIER_AUDIENCE?: string;
  VERIFIER_AUDIENCES?: string;
  VERIFIER_SERVICE_TOKEN?: string;
  REVOCATION_CACHE?: KVNamespace;
};

const app = new Hono<{ Bindings: Env }>();

const logger = createLogger({ base: { app: "verifier" } });
app.use("*", requestLogger(logger, "verifier"));
app.use("*", async (c, next) => {
  await next();
  const headers = securityHeaders({ production: c.env.ENVIRONMENT === "production" });
  for (const [k, v] of Object.entries(headers)) c.header(k, v);
});
app.use("/v1/*", bodyLimit({ maxSize: 16 * 1024 }));

app.get("/health", (c) => c.json({ ok: true }));

export const allowedAudiences = (env: Pick<Env, "VERIFIER_AUDIENCE" | "VERIFIER_AUDIENCES">) =>
  (env.VERIFIER_AUDIENCES ?? env.VERIFIER_AUDIENCE ?? "pact-mcp")
    .split(",")
    .map((v) => v.trim())
    .filter((v) => v.length > 0);

app.post("/v1/verify", async (c) => {
  const serviceToken = c.env.VERIFIER_SERVICE_TOKEN?.trim();
  if (!serviceToken && c.env.ENVIRONMENT === "production") {
    return c.json({ error: "misconfigured", message: "verifier service token is required" }, 503);
  }
  if (serviceToken && c.env.ENVIRONMENT === "production" && !isStrongSharedSecret(serviceToken)) {
    return c.json({ error: "misconfigured", message: "verifier service token is too weak" }, 503);
  }
  if (serviceToken) {
    const expected = `Bearer ${serviceToken}`;
    const received = c.req.header("Authorization") ?? "";
    if (!timingSafeEqualString(received, expected)) {
      return c.json({ error: "unauthorized", message: "invalid service token" }, 401);
    }
  }
  const body = await c.req.json<{
    token: string;
    action: string;
    resource: string;
    audience?: string;
  }>();
  const audience = body.audience ?? c.env.VERIFIER_AUDIENCE ?? "pact-mcp";
  if (!allowedAudiences(c.env).includes(audience)) {
    return c.json({ error: "invalid_audience", message: "audience is not allowed" }, 400);
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
  const rawMek = fromBase64(c.env.MEK);
  const cache = c.env.REVOCATION_CACHE ? kvRevocationCache(c.env.REVOCATION_CACHE) : undefined;
  let result: Awaited<ReturnType<typeof verifyAction>>;
  try {
    result = await verifyAction(
      {
        databaseUrl: c.env.DATABASE_URL,
        rawMek,
        issuer: c.env.ISSUER_BASE_URL,
        ...(cache ? { cache } : {}),
        auditRequired: c.env.ENVIRONMENT === "production",
      },
      {
        token: body.token,
        action: body.action,
        resource: body.resource,
        audience,
      },
    );
  } catch (e) {
    if (e instanceof AuditUnavailableError) {
      return c.json({ error: "audit_unavailable", message: "verifier audit is required" }, 503);
    }
    throw e;
  }
  return c.json(result, result.allow ? 200 : 403);
});

export default app;
