import { fromBase64 } from "@getpact/crypto";
import { Hono } from "hono";
import { type KVNamespace, kvRevocationCache } from "./cache.js";
import { verifyAction } from "./verify.js";

type Env = {
  DATABASE_URL: string;
  MEK: string;
  REVOCATION_CACHE?: KVNamespace;
};

const app = new Hono<{ Bindings: Env }>();

app.get("/health", (c) => c.json({ ok: true }));

app.post("/v1/verify", async (c) => {
  const body = await c.req.json<{
    token: string;
    action: string;
    resource: string;
    audience: string;
  }>();
  const rawMek = fromBase64(c.env.MEK);
  const cache = c.env.REVOCATION_CACHE ? kvRevocationCache(c.env.REVOCATION_CACHE) : undefined;
  const result = await verifyAction(
    { databaseUrl: c.env.DATABASE_URL, rawMek, ...(cache ? { cache } : {}) },
    body,
  );
  return c.json(result, result.allow ? 200 : 403);
});

export default app;
