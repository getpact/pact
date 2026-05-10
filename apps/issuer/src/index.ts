import type { Email } from "@getpact/core";
import { Hono } from "hono";
import { decodeMek, type Env, tokenTtlSeconds } from "./env.js";
import { buildWorkspaceJwks } from "./jwks.js";
import { mintTokenForEmail } from "./mint.js";
import { createWorkspace } from "./workspace.js";

const app = new Hono<{ Bindings: Env }>();

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

app.post("/v1/dev/mint", async (c) => {
  const body = await c.req.json<{ workspaceId: string; email: string; audience: string }>();
  const result = await mintTokenForEmail(c.env.DATABASE_URL, decodeMek(c.env), {
    workspaceId: body.workspaceId,
    email: body.email as Email,
    audience: body.audience,
    ttlSeconds: tokenTtlSeconds(c.env),
    issuerUrl: c.env.ISSUER_BASE_URL,
  });
  return c.json(result);
});

app.get("/v1/workspaces/:id/.well-known/jwks.json", async (c) => {
  const id = c.req.param("id");
  const jwks = await buildWorkspaceJwks(c.env.DATABASE_URL, id);
  return c.json(jwks, 200, { "cache-control": "public, max-age=300" });
});

export default app;
