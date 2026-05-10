import { fromBase64 } from "@getpact/crypto";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { type KVNamespace, kvRevocationCache } from "./cache.js";
import { verifyAction } from "./verify.js";

type Env = {
  DATABASE_URL: string;
  MEK: string;
  ISSUER_BASE_URL: string;
  VERIFIER_AUDIENCE?: string;
  REVOCATION_CACHE?: KVNamespace;
};

const app = new Hono<{ Bindings: Env }>();

app.use("/v1/*", bodyLimit({ maxSize: 16 * 1024 }));

app.get("/health", (c) => c.json({ ok: true }));

app.post("/v1/verify", async (c) => {
  const body = await c.req.json<{
    token: string;
    action: string;
    resource: string;
  }>();
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
      audience: c.env.VERIFIER_AUDIENCE ?? "pact-mcp",
    },
  );
  return c.json(result, result.allow ? 200 : 403);
});

export default app;
