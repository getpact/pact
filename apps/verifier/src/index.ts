import { securityHeaders } from "@getpact/core";
import { fromBase64 } from "@getpact/crypto";
import { createLogger, requestLogger } from "@getpact/logger";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { type KVNamespace, kvRevocationCache } from "./cache.js";
import { verifyAction } from "./verify.js";

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
  if (serviceToken) {
    const expected = `Bearer ${serviceToken}`;
    if (c.req.header("Authorization") !== expected) {
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
  const rawMek = fromBase64(c.env.MEK);
  const cache = c.env.REVOCATION_CACHE ? kvRevocationCache(c.env.REVOCATION_CACHE) : undefined;
  const result = await verifyAction(
    {
      databaseUrl: c.env.DATABASE_URL,
      rawMek,
      issuer: c.env.ISSUER_BASE_URL,
      ...(cache ? { cache } : {}),
    },
    {
      token: body.token,
      action: body.action,
      resource: body.resource,
      audience,
    },
  );
  return c.json(result, result.allow ? 200 : 403);
});

export default app;
