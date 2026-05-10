import { canonicalizeEmail, type Email } from "@getpact/core";
import { createClient, withWorkspace } from "@getpact/db";
import { groupMembers, groups, invites, policies, revokedJtis, users } from "@getpact/db/schema";
import { tryParsePolicy } from "@getpact/policy";
import { and, desc, eq, max, sql } from "drizzle-orm";
import type { Context } from "hono";
import { Hono } from "hono";
import { emitAdminAudit } from "./audit.js";
import { type AdminContext, authenticateAdmin } from "./auth.js";
import { bustRevocationCache, type KVNamespace } from "./cache.js";

type Env = {
  DATABASE_URL: string;
  MEK: string;
  ISSUER_BASE_URL: string;
  ADMIN_AUDIENCE?: string;
  REVOCATION_CACHE?: KVNamespace;
};
type AppCtx = Context<{ Bindings: Env }>;

const app = new Hono<{ Bindings: Env }>();

app.get("/health", (c) => c.json({ ok: true }));

const auth = async (c: AppCtx, workspaceId: string): Promise<AdminContext | Response> => {
  const audience = c.env.ADMIN_AUDIENCE ?? "pact-admin";
  try {
    return await authenticateAdmin(
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

const isContext = (v: unknown): v is AdminContext =>
  typeof v === "object" && v !== null && "userId" in v;

const audit = (
  c: AppCtx,
  ctx: AdminContext,
  action: string,
  target: unknown,
  decision: "allow" | "deny" = "allow",
): Promise<void> =>
  emitAdminAudit({
    databaseUrl: c.env.DATABASE_URL,
    mek: c.env.MEK,
    workspaceId: ctx.workspaceId,
    actorUserId: ctx.userId,
    action,
    target,
    decision,
  });

app.get("/v1/workspaces/:id/users", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const db = createClient(c.env.DATABASE_URL);
  const rows = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .select({ id: users.id, email: users.email, name: users.name, createdAt: users.createdAt })
      .from(users)
      .where(eq(users.workspaceId, workspaceId)),
  );
  return c.json({ users: rows });
});

app.post("/v1/workspaces/:id/users", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const body = await c.req.json<{ email: string; name?: string }>();
  const email = canonicalizeEmail(body.email) as Email;
  const db = createClient(c.env.DATABASE_URL);
  const inserted = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .insert(users)
      .values({ workspaceId, email, name: body.name ?? null })
      .returning({ id: users.id, email: users.email }),
  );
  await audit(c, ctx, "admin.user.created", { userId: inserted[0]?.id, email });
  return c.json({ user: inserted[0] }, 201);
});

app.post("/v1/workspaces/:id/groups", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const body = await c.req.json<{ name: string; description?: string }>();
  const db = createClient(c.env.DATABASE_URL);
  const inserted = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .insert(groups)
      .values({ workspaceId, name: body.name, description: body.description ?? null })
      .returning({ id: groups.id, name: groups.name }),
  );
  await audit(c, ctx, "admin.group.created", { groupId: inserted[0]?.id, name: body.name });
  return c.json({ group: inserted[0] }, 201);
});

app.post("/v1/workspaces/:id/groups/:groupId/members", async (c) => {
  const workspaceId = c.req.param("id");
  const groupId = c.req.param("groupId");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const body = await c.req.json<{ userId: string }>();
  const db = createClient(c.env.DATABASE_URL);
  await withWorkspace(db, workspaceId, (tx) =>
    tx.insert(groupMembers).values({ groupId, userId: body.userId }),
  );
  await audit(c, ctx, "admin.group_member.added", { groupId, userId: body.userId });
  return c.json({ ok: true }, 201);
});

app.post("/v1/workspaces/:id/policies", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const body = await c.req.json<{ body: unknown }>();
  const parsed = tryParsePolicy(body.body);
  if (!parsed) {
    await audit(c, ctx, "admin.policy.rejected", { reason: "invalid" }, "deny");
    return c.json({ error: "invalid policy" }, 400);
  }

  const db = createClient(c.env.DATABASE_URL);
  const created = await withWorkspace(db, workspaceId, async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`policy:${workspaceId}`}))`);

    const [latest] = await tx
      .select({ maxVersion: max(policies.version) })
      .from(policies)
      .where(eq(policies.workspaceId, workspaceId));
    const previousVersion = latest?.maxVersion ?? 0;
    const nextVersion = previousVersion + 1;

    if (previousVersion > 0) {
      await tx
        .update(policies)
        .set({ replacedAt: new Date() })
        .where(and(eq(policies.workspaceId, workspaceId), eq(policies.version, previousVersion)));
    }

    const [row] = await tx
      .insert(policies)
      .values({
        workspaceId,
        version: nextVersion,
        body: parsed,
        createdBy: ctx.userId,
      })
      .returning({ id: policies.id, version: policies.version });
    return row;
  });
  await audit(c, ctx, "admin.policy.created", {
    policyId: created?.id,
    version: created?.version,
  });
  return c.json({ policy: created }, 201);
});

app.get("/v1/workspaces/:id/policies", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const db = createClient(c.env.DATABASE_URL);
  const rows = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .select({
        id: policies.id,
        version: policies.version,
        createdAt: policies.createdAt,
        replacedAt: policies.replacedAt,
      })
      .from(policies)
      .where(eq(policies.workspaceId, workspaceId))
      .orderBy(desc(policies.version)),
  );
  return c.json({ policies: rows });
});

app.post("/v1/workspaces/:id/revocations", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const body = await c.req.json<{ jti: string; reason?: string }>();
  const db = createClient(c.env.DATABASE_URL);
  await withWorkspace(db, workspaceId, (tx) =>
    tx.insert(revokedJtis).values({
      workspaceId,
      jti: body.jti,
      revokedBy: ctx.userId,
      reason: body.reason ?? null,
    }),
  );
  await bustRevocationCache(c.env.REVOCATION_CACHE, workspaceId, body.jti);
  await audit(c, ctx, "admin.revocation.created", { jti: body.jti, reason: body.reason });
  return c.json({ ok: true }, 201);
});

app.post("/v1/workspaces/:id/invites", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const body = await c.req.json<{
    email: string;
    scope: unknown;
    ttl: "1d" | "1w" | "1m";
  }>();
  const ttlSeconds = body.ttl === "1d" ? 86_400 : body.ttl === "1w" ? 604_800 : 2_592_000;
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
  const db = createClient(c.env.DATABASE_URL);
  const inserted = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .insert(invites)
      .values({
        workspaceId,
        email: canonicalizeEmail(body.email),
        scope: body.scope,
        ttl: body.ttl,
        expiresAt,
        createdBy: ctx.userId,
      })
      .returning({ id: invites.id, email: invites.email, expiresAt: invites.expiresAt }),
  );
  await audit(c, ctx, "admin.invite.created", {
    inviteId: inserted[0]?.id,
    email: inserted[0]?.email,
    ttl: body.ttl,
  });
  return c.json({ invite: inserted[0] }, 201);
});

export default app;
