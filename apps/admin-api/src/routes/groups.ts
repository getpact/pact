import { writeEvent } from "@getpact/audit";
import { authenticateBearer } from "@getpact/auth";
import { AuthzError, canonicalizeEmail, isUuid, PactError } from "@getpact/core";
import { fromBase64 } from "@getpact/crypto";
import {
  assertSafeRuntimeDbRole,
  createClient,
  type Tx,
  UnsafeRuntimeDbRoleError,
  withWorkspace,
} from "@getpact/db";
import { groupMembers, groups, users, workspaces } from "@getpact/db/schema";
import { loadActiveSigningKey } from "@getpact/keystore";
import { and, asc, eq, isNull, sql } from "drizzle-orm";
import type { Context, Hono } from "hono";

type GroupsEnv = {
  DATABASE_URL: string;
  MEK: string;
  ISSUER_BASE_URL: string;
  ENVIRONMENT?: string;
  ADMIN_AUDIENCE?: string;
};

type GroupsAuthContext = {
  workspaceId: string;
  userId: string;
  email: string;
  roles: string[];
};

type AppCtx = Context<{ Bindings: GroupsEnv }>;

const NAME_MAX = 80;
const DESCRIPTION_MAX = 280;

const authenticate = async (
  databaseUrl: string,
  workspaceId: string,
  authHeader: string | undefined,
  audience: string,
  issuer: string,
): Promise<GroupsAuthContext> => {
  const { claims } = await authenticateBearer({
    databaseUrl,
    authHeader,
    audience,
    issuer,
    expectedWorkspaceId: workspaceId,
  });
  if (!claims.roles.includes("admin")) {
    throw new AuthzError("admin role required");
  }
  return {
    workspaceId: claims.workspaceId,
    userId: claims.userId,
    email: claims.email,
    roles: claims.roles,
  };
};

const auth = async (c: AppCtx, workspaceId: string): Promise<GroupsAuthContext | Response> => {
  const audience = c.env.ADMIN_AUDIENCE ?? "pact-admin";
  try {
    await assertSafeRuntimeDbRole(c.env.DATABASE_URL, {
      production: c.env.ENVIRONMENT === "production",
    });
    return await authenticate(
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

const isAuth = (v: unknown): v is GroupsAuthContext =>
  typeof v === "object" && v !== null && "userId" in v;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const requireWorkspaceParam = (c: AppCtx): string | Response => {
  const id = c.req.param("workspaceId");
  if (!id || !isUuid(id)) {
    return c.json({ error: "invalid_request", message: "workspace id must be a uuid" }, 400);
  }
  return id;
};

const writeGroupAudit = async (
  tx: Tx,
  input: {
    workspaceId: string;
    rawMek: Uint8Array;
    actorUserId: string;
    action: string;
    target: unknown;
    decision: "allow" | "deny";
    supporting?: unknown;
  },
): Promise<void> => {
  const [ws] = await tx
    .select({ createdAt: workspaces.createdAt })
    .from(workspaces)
    .where(eq(workspaces.id, input.workspaceId))
    .limit(1);
  if (!ws) throw new Error("workspace not found for group audit");
  const auditKey = await loadActiveSigningKey(tx, input.workspaceId, "audit", input.rawMek);
  await writeEvent(tx, {
    workspaceId: input.workspaceId,
    workspaceCreatedAt: ws.createdAt,
    signingKeyId: auditKey.id,
    signingKey: auditKey.privateKey,
    event: {
      actorKind: "admin",
      actorId: input.actorUserId,
      action: input.action,
      target: input.target,
      decision: input.decision,
      supporting: input.supporting ?? null,
    },
  });
};

const resolveUser = async (
  tx: Tx,
  workspaceId: string,
  raw: string,
): Promise<{ id: string; email: string } | null> => {
  if (isUuid(raw)) {
    const rows = await tx
      .select({ id: users.id, email: users.email })
      .from(users)
      .where(and(eq(users.workspaceId, workspaceId), eq(users.id, raw)))
      .limit(1);
    return rows[0] ?? null;
  }
  const email = canonicalizeEmail(raw);
  const rows = await tx
    .select({ id: users.id, email: users.email })
    .from(users)
    .where(and(eq(users.workspaceId, workspaceId), eq(users.email, email)))
    .limit(1);
  return rows[0] ?? null;
};

const serializeGroup = (row: {
  id: string;
  name: string;
  description: string | null;
  createdAt: Date;
  revokedAt: Date | null;
}) => ({
  id: row.id,
  name: row.name,
  description: row.description,
  created_at: row.createdAt.toISOString(),
  revoked_at: row.revokedAt ? row.revokedAt.toISOString() : null,
});

const isUniqueViolation = (err: unknown): boolean =>
  !!err && typeof err === "object" && "code" in err && (err as { code?: unknown }).code === "23505";

export const registerGroupRoutes = <T extends { Bindings: GroupsEnv }>(app: Hono<T>): void => {
  app.post("/v1/workspaces/:workspaceId/groups", async (c) => {
    const workspaceId = requireWorkspaceParam(c as unknown as AppCtx);
    if (typeof workspaceId !== "string") return workspaceId;
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
    if (!isAuth(ctx)) return ctx;

    let body: { name?: unknown; description?: unknown };
    try {
      body = (await c.req.json()) as { name?: unknown; description?: unknown };
    } catch {
      return c.json({ error: "invalid_body", message: "invalid json body" }, 400);
    }
    if (!isRecord(body)) {
      return c.json({ error: "invalid_body", message: "body must be an object" }, 400);
    }
    if (typeof body.name !== "string" || body.name.length === 0 || body.name.length > NAME_MAX) {
      return c.json({ error: "invalid_body", message: "name is required" }, 400);
    }
    let description: string | null = null;
    if (body.description !== undefined && body.description !== null) {
      if (typeof body.description !== "string" || body.description.length > DESCRIPTION_MAX) {
        return c.json({ error: "invalid_body", message: "description too long" }, 400);
      }
      description = body.description;
    }

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = fromBase64(c.env.MEK);
    try {
      const inserted = await withWorkspace(db, workspaceId, async (tx) => {
        const rows = await tx
          .insert(groups)
          .values({ workspaceId, name: body.name as string, description })
          .returning();
        const row = rows[0];
        if (!row) throw new Error("group insert returned no row");
        await writeGroupAudit(tx, {
          workspaceId,
          rawMek,
          actorUserId: ctx.userId,
          action: "group.created",
          target: { group_id: row.id, name: row.name },
          decision: "allow",
        });
        return row;
      });
      return c.json({ group: serializeGroup(inserted) }, 201);
    } catch (e) {
      if (isUniqueViolation(e)) {
        return c.json({ error: "conflict", message: "group name already exists" }, 409);
      }
      const message = e instanceof Error ? e.message : "create failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });

  app.get("/v1/workspaces/:workspaceId/groups", async (c) => {
    const workspaceId = requireWorkspaceParam(c as unknown as AppCtx);
    if (typeof workspaceId !== "string") return workspaceId;
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
    if (!isAuth(ctx)) return ctx;

    const db = createClient(c.env.DATABASE_URL);
    try {
      const rows = await withWorkspace(db, workspaceId, (tx) =>
        tx
          .select()
          .from(groups)
          .where(and(eq(groups.workspaceId, workspaceId), isNull(groups.revokedAt)))
          .orderBy(asc(groups.createdAt)),
      );
      return c.json({ groups: rows.map(serializeGroup) });
    } catch (e) {
      const message = e instanceof Error ? e.message : "list failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });

  app.post("/v1/workspaces/:workspaceId/groups/:groupId/members", async (c) => {
    const workspaceId = requireWorkspaceParam(c as unknown as AppCtx);
    if (typeof workspaceId !== "string") return workspaceId;
    const groupId = c.req.param("groupId");
    if (!groupId || !isUuid(groupId)) {
      return c.json({ error: "invalid_request", message: "group id must be a uuid" }, 400);
    }
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
    if (!isAuth(ctx)) return ctx;

    let body: { user_id?: unknown; email?: unknown };
    try {
      body = (await c.req.json()) as { user_id?: unknown; email?: unknown };
    } catch {
      return c.json({ error: "invalid_body", message: "invalid json body" }, 400);
    }
    if (!isRecord(body)) {
      return c.json({ error: "invalid_body", message: "body must be an object" }, 400);
    }
    const lookup =
      typeof body.user_id === "string"
        ? body.user_id
        : typeof body.email === "string"
          ? body.email
          : null;
    if (!lookup) {
      return c.json({ error: "invalid_body", message: "user_id or email is required" }, 400);
    }

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = fromBase64(c.env.MEK);
    try {
      const outcome = await withWorkspace(db, workspaceId, async (tx) => {
        const [group] = await tx
          .select({ id: groups.id })
          .from(groups)
          .where(
            and(
              eq(groups.workspaceId, workspaceId),
              eq(groups.id, groupId),
              isNull(groups.revokedAt),
            ),
          )
          .limit(1);
        if (!group) return { kind: "group_not_found" as const };
        const subject = await resolveUser(tx, workspaceId, lookup);
        if (!subject) return { kind: "user_not_found" as const };
        await tx.execute(
          sql`INSERT INTO group_members (workspace_id, group_id, user_id)
              VALUES (${workspaceId}, ${groupId}, ${subject.id})
              ON CONFLICT (group_id, user_id)
              DO UPDATE SET revoked_at = NULL, added_at = now()`,
        );
        await writeGroupAudit(tx, {
          workspaceId,
          rawMek,
          actorUserId: ctx.userId,
          action: "group.member.added",
          target: { group_id: groupId, user_id: subject.id, email: subject.email },
          decision: "allow",
        });
        return { kind: "ok" as const, userId: subject.id, email: subject.email };
      });
      if (outcome.kind === "group_not_found") {
        return c.json({ error: "not_found", message: "group not found" }, 404);
      }
      if (outcome.kind === "user_not_found") {
        return c.json({ error: "not_found", message: "user not found" }, 404);
      }
      return c.json(
        { ok: true, group_id: groupId, user_id: outcome.userId, email: outcome.email },
        201,
      );
    } catch (e) {
      const message = e instanceof Error ? e.message : "add member failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });

  app.delete("/v1/workspaces/:workspaceId/groups/:groupId/members/:userId", async (c) => {
    const workspaceId = requireWorkspaceParam(c as unknown as AppCtx);
    if (typeof workspaceId !== "string") return workspaceId;
    const groupId = c.req.param("groupId");
    const userId = c.req.param("userId");
    if (!groupId || !isUuid(groupId) || !userId || !isUuid(userId)) {
      return c.json(
        { error: "invalid_request", message: "group id and user id must be uuids" },
        400,
      );
    }
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
    if (!isAuth(ctx)) return ctx;

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = fromBase64(c.env.MEK);
    try {
      const removed = await withWorkspace(db, workspaceId, async (tx) => {
        const updated = await tx
          .update(groupMembers)
          .set({ revokedAt: new Date() })
          .where(
            and(
              eq(groupMembers.workspaceId, workspaceId),
              eq(groupMembers.groupId, groupId),
              eq(groupMembers.userId, userId),
              isNull(groupMembers.revokedAt),
            ),
          )
          .returning({ id: groupMembers.id });
        if (updated.length === 0) return { kind: "not_found" as const };
        await writeGroupAudit(tx, {
          workspaceId,
          rawMek,
          actorUserId: ctx.userId,
          action: "group.member.revoked",
          target: { group_id: groupId, user_id: userId },
          decision: "allow",
        });
        return { kind: "ok" as const };
      });
      if (removed.kind === "not_found") {
        return c.json({ error: "not_found", message: "membership not found" }, 404);
      }
      return c.json({ ok: true });
    } catch (e) {
      const message = e instanceof Error ? e.message : "remove member failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });
};
