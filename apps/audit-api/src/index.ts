import { createClient, withWorkspace } from "@getpact/db";
import { auditChainState, workspaceSigningKeys, workspaces } from "@getpact/db/schema";
import { and, eq } from "drizzle-orm";
import type { Context } from "hono";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { type AuditAuthContext, authenticateAuditReader } from "./auth.js";
import { parseCursor, queryEvents } from "./query.js";

type Env = {
  DATABASE_URL: string;
  ISSUER_BASE_URL: string;
  AUDIT_AUDIENCE?: string;
};
type AppCtx = Context<{ Bindings: Env }>;

const MAX_LIMIT = 200;
const DEFAULT_LIMIT = 50;

const app = new Hono<{ Bindings: Env }>();

app.use("/v1/*", bodyLimit({ maxSize: 16 * 1024 }));

app.get("/health", (c) => c.json({ ok: true }));

const auth = async (c: AppCtx, workspaceId: string): Promise<AuditAuthContext | Response> => {
  const audience = c.env.AUDIT_AUDIENCE ?? "pact-audit";
  try {
    return await authenticateAuditReader(
      c.env.DATABASE_URL,
      workspaceId,
      c.req.header("Authorization"),
      audience,
      c.env.ISSUER_BASE_URL,
    );
  } catch (e) {
    const message = e instanceof Error ? e.message : "auth failed";
    return c.json({ error: "unauthorized", message }, 401);
  }
};

const isAuth = (v: unknown): v is AuditAuthContext =>
  typeof v === "object" && v !== null && "userId" in v;

app.get("/v1/workspaces/:id/audit/events", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isAuth(ctx)) return ctx;

  const url = new URL(c.req.url);
  const action = url.searchParams.get("action") ?? undefined;
  const sinceRaw = url.searchParams.get("since");
  const untilRaw = url.searchParams.get("until");
  const limitRaw = Number.parseInt(url.searchParams.get("limit") ?? "", 10);
  const cursorRaw = url.searchParams.get("cursor") ?? undefined;
  const cursor = parseCursor(cursorRaw);
  const orderRaw = url.searchParams.get("order");
  const order = orderRaw === "asc" ? "asc" : "desc";

  const since = sinceRaw ? new Date(sinceRaw) : undefined;
  const until = untilRaw ? new Date(untilRaw) : undefined;
  if (since && Number.isNaN(since.valueOf())) return c.json({ error: "invalid since" }, 400);
  if (until && Number.isNaN(until.valueOf())) return c.json({ error: "invalid until" }, 400);
  if (cursorRaw && !cursor) return c.json({ error: "invalid cursor" }, 400);

  const limit =
    Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, MAX_LIMIT) : DEFAULT_LIMIT;

  const db = createClient(c.env.DATABASE_URL);
  const out = await withWorkspace(db, workspaceId, (tx) =>
    queryEvents(tx, {
      workspaceId,
      ...(action ? { action } : {}),
      ...(since ? { since } : {}),
      ...(until ? { until } : {}),
      limit,
      order,
      ...(cursor ? { cursor } : {}),
    }),
  );
  return c.json(out);
});

app.get("/v1/workspaces/:id/audit/keys", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isAuth(ctx)) return ctx;

  const db = createClient(c.env.DATABASE_URL);
  const rows = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .select({
        id: workspaceSigningKeys.id,
        publicKeySpki: workspaceSigningKeys.publicKeySpki,
        createdAt: workspaceSigningKeys.createdAt,
        validForVerificationUntil: workspaceSigningKeys.validForVerificationUntil,
      })
      .from(workspaceSigningKeys)
      .where(
        and(
          eq(workspaceSigningKeys.workspaceId, workspaceId),
          eq(workspaceSigningKeys.kind, "audit"),
        ),
      ),
  );
  return c.json({
    keys: rows.map((r) => ({
      id: r.id,
      publicKeySpki: r.publicKeySpki,
      createdAt: r.createdAt.toISOString(),
      validForVerificationUntil: r.validForVerificationUntil?.toISOString() ?? null,
    })),
  });
});

app.get("/v1/workspaces/:id/audit/workspace", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isAuth(ctx)) return ctx;

  const db = createClient(c.env.DATABASE_URL);
  const [ws] = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .select({ id: workspaces.id, slug: workspaces.slug, createdAt: workspaces.createdAt })
      .from(workspaces)
      .where(eq(workspaces.id, workspaceId))
      .limit(1),
  );
  if (!ws) return c.json({ error: "not found" }, 404);
  return c.json({
    id: ws.id,
    slug: ws.slug,
    createdAt: ws.createdAt.toISOString(),
  });
});

app.get("/v1/workspaces/:id/audit/chain", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isAuth(ctx)) return ctx;

  const db = createClient(c.env.DATABASE_URL);
  const [head] = await withWorkspace(db, workspaceId, (tx) =>
    tx.select().from(auditChainState).where(eq(auditChainState.workspaceId, workspaceId)).limit(1),
  );
  if (!head) return c.json({ head: null });
  return c.json({
    head: {
      lastHash: head.lastHash,
      lastEventId: head.lastEventId,
      updatedAt: head.updatedAt.toISOString(),
    },
  });
});

export default app;
