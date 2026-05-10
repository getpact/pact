import { fromBase64 } from "@getpact/crypto";
import { Hono } from "hono";
import { verifyAction } from "./verify.js";

type Env = { DATABASE_URL: string; MEK: string };

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
  const result = await verifyAction(c.env.DATABASE_URL, rawMek, body);
  return c.json(result, result.allow ? 200 : 403);
});

export default app;
