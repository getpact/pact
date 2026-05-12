import { PactError, securityHeaders } from "@getpact/core";
import { fromBase64 } from "@getpact/crypto";
import { assertSafeRuntimeDbRole, UnsafeRuntimeDbRoleError } from "@getpact/db";
import { createLogger, requestLogger } from "@getpact/logger";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { authenticate } from "./auth.js";
import { handleMcp } from "./handler.js";
import { httpVerifyClient } from "./verify-client.js";

type Env = {
  DATABASE_URL: string;
  ISSUER_BASE_URL: string;
  ENVIRONMENT?: string;
  MEK?: string;
  MCP_AUDIENCE?: string;
  VERIFIER_URL?: string;
  VERIFIER_SERVICE?: { fetch: (request: Request) => Promise<Response> };
  VERIFIER_SERVICE_TOKEN?: string;
  GOOGLE_OAUTH_CLIENT_ID?: string;
  GOOGLE_OAUTH_CLIENT_SECRET?: string;
  GOOGLE_OAUTH_TOKEN_ENDPOINT?: string;
};

const app = new Hono<{ Bindings: Env }>();

const logger = createLogger({ base: { app: "mcp-server" } });
app.use("*", requestLogger(logger, "mcp-server"));
app.use("*", async (c, next) => {
  await next();
  const headers = securityHeaders({ production: c.env.ENVIRONMENT === "production" });
  for (const [k, v] of Object.entries(headers)) c.header(k, v);
});
app.use("/:workspace/mcp", bodyLimit({ maxSize: 256 * 1024 }));

app.get("/health", (c) => c.json({ ok: true }));

app.post("/:workspace/mcp", async (c) => {
  const workspace = c.req.param("workspace");
  const audience = c.env.MCP_AUDIENCE ?? "pact-mcp";
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
  if (
    c.env.ENVIRONMENT === "production" &&
    (!c.env.GOOGLE_OAUTH_CLIENT_ID || !c.env.GOOGLE_OAUTH_CLIENT_SECRET)
  ) {
    return c.json({ error: "misconfigured", message: "google oauth is not configured" }, 503);
  }

  let ctx: Awaited<ReturnType<typeof authenticate>>;
  try {
    ctx = await authenticate(
      c.env.DATABASE_URL,
      workspace,
      c.req.header("Authorization"),
      audience,
      c.env.ISSUER_BASE_URL,
    );
  } catch (e) {
    if (e instanceof PactError) {
      return c.json({ error: e.code, message: e.message }, e.status as 400 | 401 | 403 | 404);
    }
    const message = e instanceof Error ? e.message : "auth failed";
    return c.json({ error: "unauthorized", message }, 401);
  }

  const body = await c.req.json();
  const verifier = c.env.VERIFIER_SERVICE ?? c.env.VERIFIER_URL;
  const verify = verifier ? httpVerifyClient(verifier, c.env.VERIFIER_SERVICE_TOKEN) : undefined;
  const response = await handleMcp(body, ctx, {
    audience,
    deps: {
      databaseUrl: c.env.DATABASE_URL,
      ...(c.env.MEK ? { rawMek: fromBase64(c.env.MEK) } : {}),
      providerConfig: {
        GOOGLE_OAUTH_CLIENT_ID: c.env.GOOGLE_OAUTH_CLIENT_ID,
        GOOGLE_OAUTH_CLIENT_SECRET: c.env.GOOGLE_OAUTH_CLIENT_SECRET,
        GOOGLE_OAUTH_TOKEN_ENDPOINT: c.env.GOOGLE_OAUTH_TOKEN_ENDPOINT,
      },
    },
    ...(verify ? { verify } : {}),
  });
  return c.json(response);
});

export default app;
