import {
  assertAllowedUpstreamHost,
  assertSafeUpstreamUrl,
  ConflictError,
  canonicalizeEmail,
  type Email,
  PactError,
  securityHeaders,
  ValidationError,
} from "@getpact/core";
import { fromBase64 } from "@getpact/crypto";
import {
  assertSafeRuntimeDbRole,
  createClient,
  type Tx,
  UnsafeRuntimeDbRoleError,
  withWorkspace,
} from "@getpact/db";
import {
  brains,
  groupMembers,
  groups,
  invites,
  policies,
  revokedJtis,
  users,
} from "@getpact/db/schema";
import { createLogger, requestLogger } from "@getpact/logger";
import { tryParsePolicy } from "@getpact/policy";
import { deleteSecret, storeSecret } from "@getpact/vault";
import { and, desc, eq, max, sql } from "drizzle-orm";
import type { Context } from "hono";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { writeAdminAudit } from "./audit.js";
import { type AdminContext, authenticateAdmin } from "./auth.js";
import { bustRevocationCache, type KVNamespace } from "./cache.js";

type Env = {
  DATABASE_URL: string;
  MEK: string;
  ISSUER_BASE_URL: string;
  ENVIRONMENT?: string;
  ADMIN_AUDIENCE?: string;
  UPSTREAM_HOST_ALLOWLIST?: string;
  REVOCATION_CACHE?: KVNamespace;
};
type AppCtx = Context<{ Bindings: Env }>;

const app = new Hono<{ Bindings: Env }>();

const logger = createLogger({ base: { app: "admin-api" } });
app.use("*", requestLogger(logger, "admin-api"));
app.use("*", async (c, next) => {
  await next();
  const headers = securityHeaders({ production: c.env.ENVIRONMENT === "production" });
  for (const [k, v] of Object.entries(headers)) c.header(k, v);
});
app.use("/v1/*", bodyLimit({ maxSize: 64 * 1024 }));

app.get("/health", (c) => c.json({ ok: true }));

const auth = async (c: AppCtx, workspaceId: string): Promise<AdminContext | Response> => {
  const audience = c.env.ADMIN_AUDIENCE ?? "pact-admin";
  try {
    await assertSafeRuntimeDbRole(c.env.DATABASE_URL, {
      production: c.env.ENVIRONMENT === "production",
    });
    return await authenticateAdmin(
      c.env.DATABASE_URL,
      workspaceId,
      c.req.header("Authorization"),
      audience,
      c.env.ISSUER_BASE_URL,
    );
  } catch (e) {
    if (e instanceof UnsafeRuntimeDbRoleError) {
      return c.json({ error: "misconfigured", message: "unsafe runtime database role" }, 503);
    }
    if (e instanceof PactError) {
      return c.json({ error: e.code, message: e.message }, e.status as 400 | 401 | 403 | 404);
    }
    const message = e instanceof Error ? e.message : "auth failed";
    return c.json({ error: "unauthorized", message }, 401);
  }
};

const isContext = (v: unknown): v is AdminContext =>
  typeof v === "object" && v !== null && "userId" in v;

const auditInTx = (
  tx: Tx,
  c: AppCtx,
  ctx: AdminContext,
  action: string,
  target: unknown,
  decision: "allow" | "deny" = "allow",
): Promise<void> =>
  writeAdminAudit(tx, {
    rawMek: fromBase64(c.env.MEK),
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
  const inserted = await withWorkspace(db, workspaceId, async (tx) => {
    const rows = await tx
      .insert(users)
      .values({ workspaceId, email, name: body.name ?? null })
      .returning({ id: users.id, email: users.email });
    await auditInTx(tx, c, ctx, "admin.user.created", { userId: rows[0]?.id, email });
    return rows;
  });
  return c.json({ user: inserted[0] }, 201);
});

app.post("/v1/workspaces/:id/groups", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const body = await c.req.json<{ name: string; description?: string }>();
  const db = createClient(c.env.DATABASE_URL);
  const inserted = await withWorkspace(db, workspaceId, async (tx) => {
    const rows = await tx
      .insert(groups)
      .values({ workspaceId, name: body.name, description: body.description ?? null })
      .returning({ id: groups.id, name: groups.name });
    await auditInTx(tx, c, ctx, "admin.group.created", {
      groupId: rows[0]?.id,
      name: body.name,
    });
    return rows;
  });
  return c.json({ group: inserted[0] }, 201);
});

app.post("/v1/workspaces/:id/groups/:groupId/members", async (c) => {
  const workspaceId = c.req.param("id");
  const groupId = c.req.param("groupId");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const body = await c.req.json<{ userId: string }>();
  const db = createClient(c.env.DATABASE_URL);
  await withWorkspace(db, workspaceId, async (tx) => {
    await tx.insert(groupMembers).values({ groupId, userId: body.userId });
    await auditInTx(tx, c, ctx, "admin.group_member.added", { groupId, userId: body.userId });
  });
  return c.json({ ok: true }, 201);
});

app.post("/v1/workspaces/:id/policies", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const body = await c.req.json<{ body: unknown }>();
  const parsed = tryParsePolicy(body.body);
  if (!parsed) {
    try {
      const db = createClient(c.env.DATABASE_URL);
      await withWorkspace(db, workspaceId, (tx) =>
        auditInTx(tx, c, ctx, "admin.policy.rejected", { reason: "invalid" }, "deny"),
      );
    } catch {
      return c.json({ error: "audit_unavailable" }, 503);
    }
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
    await auditInTx(tx, c, ctx, "admin.policy.created", {
      policyId: row?.id,
      version: row?.version,
    });
    return row;
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
  await withWorkspace(db, workspaceId, async (tx) => {
    await tx.insert(revokedJtis).values({
      workspaceId,
      jti: body.jti,
      revokedBy: ctx.userId,
      reason: body.reason ?? null,
    });
    await tx.execute(
      sql`UPDATE refresh_tokens
          SET revoked_at = COALESCE(revoked_at, NOW())
          WHERE workspace_id = ${workspaceId}
            AND access_jti = ${body.jti}
            AND revoked_at IS NULL`,
    );
    await auditInTx(tx, c, ctx, "admin.revocation.created", {
      jti: body.jti,
      reason: body.reason,
    });
  });
  await bustRevocationCache(c.env.REVOCATION_CACHE, workspaceId, body.jti);
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
  const inserted = await withWorkspace(db, workspaceId, async (tx) => {
    const rows = await tx
      .insert(invites)
      .values({
        workspaceId,
        email: canonicalizeEmail(body.email),
        scope: body.scope,
        ttl: body.ttl,
        expiresAt,
        createdBy: ctx.userId,
      })
      .returning({ id: invites.id, email: invites.email, expiresAt: invites.expiresAt });
    await auditInTx(tx, c, ctx, "admin.invite.created", {
      inviteId: rows[0]?.id,
      email: rows[0]?.email,
      ttl: body.ttl,
    });
    return rows;
  });
  return c.json({ invite: inserted[0] }, 201);
});

const KIND_RE = /^[a-z][a-z0-9-]{0,32}$/;
const pgErrorCode = (value: unknown): string | null => {
  if (typeof value !== "object" || value === null || !("code" in value)) return null;
  const code = (value as { code?: unknown }).code;
  return typeof code === "string" ? code : null;
};

const isUniqueViolation = (value: unknown): boolean => pgErrorCode(value) === "23505";

app.post("/v1/workspaces/:id/brains", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  try {
    let body: {
      kind: string;
      baseUrl: string;
      authScheme?: string;
    };
    try {
      body = await c.req.json();
    } catch {
      throw new ValidationError("invalid json body");
    }
    if (!body || typeof body !== "object") {
      throw new ValidationError("request body must be an object");
    }
    if (typeof body.kind !== "string" || !KIND_RE.test(body.kind)) {
      throw new ValidationError("invalid kind");
    }
    if (typeof body.baseUrl !== "string") throw new ValidationError("baseUrl required");
    const upstreamUrl = assertSafeUpstreamUrl(body.baseUrl);
    assertAllowedUpstreamHost(upstreamUrl, c.env.UPSTREAM_HOST_ALLOWLIST, {
      required: c.env.ENVIRONMENT === "production",
    });
    const authScheme = body.authScheme ?? "none";
    if (authScheme !== "none" && authScheme !== "bearer") {
      throw new ValidationError("authScheme must be none or bearer");
    }

    const db = createClient(c.env.DATABASE_URL);
    const inserted = await withWorkspace(db, workspaceId, async (tx) => {
      try {
        const rows = await tx
          .insert(brains)
          .values({
            workspaceId,
            kind: body.kind,
            baseUrl: body.baseUrl,
            authScheme,
          })
          .returning({ id: brains.id, kind: brains.kind, baseUrl: brains.baseUrl });
        await auditInTx(tx, c, ctx, "admin.brain.created", {
          brainId: rows[0]?.id,
          kind: body.kind,
        });
        return rows;
      } catch (e) {
        if (isUniqueViolation(e)) throw new ConflictError("brain kind already exists");
        throw e;
      }
    });
    return c.json({ brain: inserted[0] }, 201);
  } catch (e) {
    if (e instanceof PactError) {
      return c.json({ error: e.code, message: e.message }, e.status as 400 | 409);
    }
    throw e;
  }
});

app.get("/v1/workspaces/:id/brains", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const db = createClient(c.env.DATABASE_URL);
  const rows = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .select({
        id: brains.id,
        kind: brains.kind,
        baseUrl: brains.baseUrl,
        authScheme: brains.authScheme,
        status: brains.status,
        createdAt: brains.createdAt,
      })
      .from(brains)
      .where(eq(brains.workspaceId, workspaceId)),
  );
  return c.json({ brains: rows });
});

app.delete("/v1/workspaces/:id/brains/:brainId", async (c) => {
  const workspaceId = c.req.param("id");
  const brainId = c.req.param("brainId");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const db = createClient(c.env.DATABASE_URL);
  const removed = await withWorkspace(db, workspaceId, async (tx) => {
    const rows = await tx
      .delete(brains)
      .where(and(eq(brains.workspaceId, workspaceId), eq(brains.id, brainId)))
      .returning({ id: brains.id, kind: brains.kind });
    const kind = rows[0]?.kind;
    if (kind) {
      await deleteSecret(tx, {
        workspaceId,
        kind: "brain_credential",
        target: brainId,
      });
      await auditInTx(tx, c, ctx, "admin.brain.deleted", { brainId, kind });
    }
    return rows;
  });
  if (removed.length === 0) {
    return c.json({ error: "not_found", message: "brain not found" }, 404);
  }
  return c.json({ ok: true });
});

app.put("/v1/workspaces/:id/brains/:brainId/credential", async (c) => {
  const workspaceId = c.req.param("id");
  const brainId = c.req.param("brainId");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  try {
    const body = await c.req.json<{ token: string }>();
    if (!body || typeof body.token !== "string" || body.token.length === 0) {
      throw new ValidationError("token required");
    }
    if (/[\r\n\t]/.test(body.token)) {
      throw new ValidationError("token contains illegal whitespace");
    }
    if (body.token.length > 4096) {
      throw new ValidationError("token too long");
    }

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = fromBase64(c.env.MEK);
    const result = await withWorkspace(db, workspaceId, async (tx) => {
      const [brainRow] = await tx
        .select({ kind: brains.kind, authScheme: brains.authScheme })
        .from(brains)
        .where(and(eq(brains.workspaceId, workspaceId), eq(brains.id, brainId)))
        .limit(1);
      if (!brainRow) return "not_found" as const;
      if (brainRow.authScheme !== "bearer") {
        throw new ValidationError("brain authScheme must be bearer to store credential");
      }
      await storeSecret(tx, rawMek, {
        workspaceId,
        kind: "brain_credential",
        target: brainId,
        plaintext: body.token,
      });
      await auditInTx(tx, c, ctx, "admin.brain.credential.set", { brainId, kind: brainRow.kind });
      return "ok" as const;
    });
    if (result === "not_found")
      return c.json({ error: "not_found", message: "brain not found" }, 404);
    return c.json({ ok: true });
  } catch (e) {
    if (e instanceof PactError) {
      return c.json({ error: e.code, message: e.message }, e.status as 400 | 404);
    }
    throw e;
  }
});

export default app;
