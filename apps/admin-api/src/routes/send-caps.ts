import { writeEvent } from "@getpact/audit";
import { authenticateBearer } from "@getpact/auth";
import { AuthzError, isUuid, PactError } from "@getpact/core";
import { fromBase64 } from "@getpact/crypto";
import {
  assertSafeRuntimeDbRole,
  createClient,
  type Tx,
  UnsafeRuntimeDbRoleError,
  withWorkspace,
} from "@getpact/db";
import { sendCaps, users, workspaces } from "@getpact/db/schema";
import { loadActiveSigningKey } from "@getpact/keystore";
import { and, asc, eq, isNull, sql } from "drizzle-orm";
import type { Context, Hono } from "hono";

type SendCapsEnv = {
  DATABASE_URL: string;
  MEK: string;
  ISSUER_BASE_URL: string;
  ENVIRONMENT?: string;
  ADMIN_AUDIENCE?: string;
};

type SendCapsAuthContext = {
  workspaceId: string;
  userId: string;
  email: string;
  roles: string[];
};

type AppCtx = Context<{ Bindings: SendCapsEnv }>;

const LIST_LIMIT_DEFAULT = 100;
const LIST_LIMIT_MAX = 500;
const REASON_MAX = 280;

const authenticate = async (
  databaseUrl: string,
  workspaceId: string,
  authHeader: string | undefined,
  audience: string,
  issuer: string,
): Promise<SendCapsAuthContext> => {
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

const auth = async (c: AppCtx, workspaceId: string): Promise<SendCapsAuthContext | Response> => {
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

const isAuth = (v: unknown): v is SendCapsAuthContext =>
  typeof v === "object" && v !== null && "userId" in v;

const writeSendCapAudit = async (
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
  if (!ws) throw new Error("workspace not found for send-cap audit");
  const auditKey = await loadActiveSigningKey(tx, input.workspaceId, "audit", input.rawMek);
  await writeEvent(tx, {
    workspaceId: input.workspaceId,
    workspaceCreatedAt: ws.createdAt,
    signingKeyId: auditKey.id,
    signingKey: auditKey.privateKey,
    event: {
      actorKind: "user",
      actorId: input.actorUserId,
      action: input.action,
      target: input.target,
      decision: input.decision,
      supporting: input.supporting ?? null,
    },
  });
};

const findWorkspaceIdForCap = async (
  databaseUrl: string,
  capId: string,
): Promise<string | null> => {
  if (!isUuid(capId)) return null;
  const db = createClient(databaseUrl);
  const rows = (await db.execute(
    sql`SELECT workspace_id FROM send_caps WHERE id = ${capId} LIMIT 1`,
  )) as Array<{ workspace_id: string }>;
  return rows[0]?.workspace_id ?? null;
};

type MintBody = {
  grantee_user_id?: unknown;
  scope_pattern?: unknown;
  max_uses?: unknown;
  expires_at?: unknown;
};

type ParsedMint = {
  granteeUserId: string;
  scopePattern: Record<string, unknown>;
  maxUses: number | null;
  expiresAt: Date | null;
};

const parseMintBody = (body: MintBody): ParsedMint | string => {
  if (typeof body.grantee_user_id !== "string" || !isUuid(body.grantee_user_id)) {
    return "grantee_user_id must be a uuid";
  }
  let scopePattern: Record<string, unknown> = {};
  if (body.scope_pattern !== undefined && body.scope_pattern !== null) {
    if (typeof body.scope_pattern !== "object" || Array.isArray(body.scope_pattern)) {
      return "scope_pattern must be an object";
    }
    scopePattern = body.scope_pattern as Record<string, unknown>;
  }
  let maxUses: number | null = null;
  if (body.max_uses !== undefined && body.max_uses !== null) {
    if (typeof body.max_uses !== "number" || !Number.isFinite(body.max_uses)) {
      return "max_uses must be an integer";
    }
    const trunc = Math.trunc(body.max_uses);
    if (trunc <= 0) return "max_uses must be positive";
    maxUses = trunc;
  }
  let expiresAt: Date | null = null;
  if (body.expires_at !== undefined && body.expires_at !== null) {
    if (typeof body.expires_at !== "string") {
      return "expires_at must be an ISO string";
    }
    const parsed = new Date(body.expires_at);
    if (Number.isNaN(parsed.valueOf())) return "expires_at is not a valid date";
    if (parsed.getTime() <= Date.now()) return "expires_at must be in the future";
    expiresAt = parsed;
  }
  return {
    granteeUserId: body.grantee_user_id,
    scopePattern,
    maxUses,
    expiresAt,
  };
};

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const serializeCap = (row: {
  id: string;
  workspaceId: string;
  issuerUserId: string;
  granteeUserId: string;
  scopePattern: unknown;
  maxUses: number | null;
  usedCount: number;
  expiresAt: Date | null;
  createdAt: Date;
  revokedAt: Date | null;
  revokedReason: string | null;
}) => ({
  id: row.id,
  workspace_id: row.workspaceId,
  issuer_user_id: row.issuerUserId,
  grantee_user_id: row.granteeUserId,
  scope_pattern: row.scopePattern,
  max_uses: row.maxUses,
  used_count: row.usedCount,
  expires_at: row.expiresAt ? row.expiresAt.toISOString() : null,
  created_at: row.createdAt.toISOString(),
  revoked_at: row.revokedAt ? row.revokedAt.toISOString() : null,
  revoked_reason: row.revokedReason,
});

export const registerSendCapRoutes = <T extends { Bindings: SendCapsEnv }>(app: Hono<T>): void => {
  app.post("/v1/send-caps", async (c) => {
    const workspaceIdHeader = c.req.header("x-pact-workspace-id");
    if (!workspaceIdHeader || !isUuid(workspaceIdHeader)) {
      return c.json(
        { error: "invalid_request", message: "x-pact-workspace-id header required" },
        400,
      );
    }

    const ctx = await auth(c as unknown as AppCtx, workspaceIdHeader);
    if (!isAuth(ctx)) return ctx;

    let body: MintBody;
    try {
      body = (await c.req.json()) as MintBody;
    } catch {
      return c.json({ error: "invalid_body", message: "invalid json body" }, 400);
    }
    if (!isRecord(body)) {
      return c.json({ error: "invalid_body", message: "body must be an object" }, 400);
    }
    const parsed = parseMintBody(body);
    if (typeof parsed === "string") {
      return c.json({ error: "invalid_body", message: parsed }, 400);
    }

    if (parsed.granteeUserId === ctx.userId) {
      return c.json({ error: "invalid_body", message: "issuer and grantee must differ" }, 400);
    }

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = fromBase64(c.env.MEK);
    try {
      const inserted = await withWorkspace(db, ctx.workspaceId, async (tx) => {
        const [grantee] = await tx
          .select({ id: users.id })
          .from(users)
          .where(and(eq(users.workspaceId, ctx.workspaceId), eq(users.id, parsed.granteeUserId)))
          .limit(1);
        if (!grantee) return { kind: "not_found" as const };

        const rows = await tx
          .insert(sendCaps)
          .values({
            workspaceId: ctx.workspaceId,
            issuerUserId: ctx.userId,
            granteeUserId: parsed.granteeUserId,
            scopePattern: parsed.scopePattern,
            maxUses: parsed.maxUses,
            expiresAt: parsed.expiresAt,
          })
          .returning();
        const row = rows[0];
        if (!row) throw new Error("send_cap insert returned no row");
        await writeSendCapAudit(tx, {
          workspaceId: ctx.workspaceId,
          rawMek,
          actorUserId: ctx.userId,
          action: "send_cap.minted",
          target: {
            send_cap_id: row.id,
            issuer_user_id: row.issuerUserId,
            grantee_user_id: row.granteeUserId,
          },
          decision: "allow",
          supporting: {
            max_uses: row.maxUses,
            expires_at: row.expiresAt ? row.expiresAt.toISOString() : null,
          },
        });
        return { kind: "ok" as const, row };
      });
      if (inserted.kind === "not_found") {
        return c.json({ error: "not_found", message: "grantee user not found" }, 404);
      }
      return c.json({ send_cap: serializeCap(inserted.row) }, 201);
    } catch (e) {
      const message = e instanceof Error ? e.message : "mint failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });

  app.get("/v1/send-caps", async (c) => {
    const workspaceIdHeader = c.req.header("x-pact-workspace-id");
    if (!workspaceIdHeader || !isUuid(workspaceIdHeader)) {
      return c.json(
        { error: "invalid_request", message: "x-pact-workspace-id header required" },
        400,
      );
    }
    const ctx = await auth(c as unknown as AppCtx, workspaceIdHeader);
    if (!isAuth(ctx)) return ctx;

    const url = new URL(c.req.url);
    const issuerParam = url.searchParams.get("issuer_user_id") ?? undefined;
    const granteeParam = url.searchParams.get("grantee_user_id") ?? undefined;
    const activeParam = url.searchParams.get("active");
    const limitRaw = url.searchParams.get("limit");
    let limit = LIST_LIMIT_DEFAULT;
    if (limitRaw !== undefined && limitRaw !== null) {
      const n = Number.parseInt(limitRaw, 10);
      if (!Number.isFinite(n) || n <= 0) {
        return c.json({ error: "invalid_query", message: "limit must be a positive integer" }, 400);
      }
      limit = Math.min(n, LIST_LIMIT_MAX);
    }
    if (issuerParam !== undefined && !isUuid(issuerParam)) {
      return c.json({ error: "invalid_query", message: "issuer_user_id must be a uuid" }, 400);
    }
    if (granteeParam !== undefined && !isUuid(granteeParam)) {
      return c.json({ error: "invalid_query", message: "grantee_user_id must be a uuid" }, 400);
    }
    const onlyActive = activeParam === "true" || activeParam === "1";

    const db = createClient(c.env.DATABASE_URL);
    try {
      const rows = await withWorkspace(db, ctx.workspaceId, (tx) => {
        const conditions = [eq(sendCaps.workspaceId, ctx.workspaceId)];
        if (issuerParam) conditions.push(eq(sendCaps.issuerUserId, issuerParam));
        if (granteeParam) conditions.push(eq(sendCaps.granteeUserId, granteeParam));
        if (onlyActive) conditions.push(isNull(sendCaps.revokedAt));
        return tx
          .select()
          .from(sendCaps)
          .where(and(...conditions))
          .orderBy(asc(sendCaps.createdAt))
          .limit(limit);
      });
      return c.json({ send_caps: rows.map(serializeCap) });
    } catch (e) {
      const message = e instanceof Error ? e.message : "list failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });

  app.delete("/v1/send-caps/:id", async (c) => {
    const id = c.req.param("id");
    if (!isUuid(id)) {
      return c.json({ error: "not_found", message: "send_cap not found" }, 404);
    }
    let body: { reason?: unknown } = {};
    const raw = await c.req.text();
    if (raw.length > 0) {
      try {
        body = JSON.parse(raw) as { reason?: unknown };
      } catch {
        return c.json({ error: "invalid_body", message: "invalid json body" }, 400);
      }
      if (!isRecord(body)) {
        return c.json({ error: "invalid_body", message: "body must be an object" }, 400);
      }
    }
    let reason: string | null = null;
    if (body.reason !== undefined && body.reason !== null) {
      if (typeof body.reason !== "string") {
        return c.json({ error: "invalid_body", message: "reason must be a string" }, 400);
      }
      if (body.reason.length > REASON_MAX) {
        return c.json({ error: "invalid_body", message: "reason too long" }, 400);
      }
      reason = body.reason;
    }

    const workspaceId = await findWorkspaceIdForCap(c.env.DATABASE_URL, id);
    if (!workspaceId) {
      return c.json({ error: "not_found", message: "send_cap not found" }, 404);
    }
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
    if (!isAuth(ctx)) return ctx;

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = fromBase64(c.env.MEK);
    try {
      const result = await withWorkspace(db, workspaceId, async (tx) => {
        const [existing] = await tx
          .select()
          .from(sendCaps)
          .where(and(eq(sendCaps.workspaceId, workspaceId), eq(sendCaps.id, id)))
          .limit(1);
        if (!existing) return { kind: "not_found" as const };
        if (existing.issuerUserId !== ctx.userId) {
          return { kind: "forbidden" as const };
        }
        if (existing.revokedAt) {
          return { kind: "ok" as const, row: existing };
        }
        const updated = await tx
          .update(sendCaps)
          .set({ revokedAt: new Date(), revokedReason: reason })
          .where(and(eq(sendCaps.workspaceId, workspaceId), eq(sendCaps.id, id)))
          .returning();
        const row = updated[0];
        if (!row) throw new Error("send_cap revoke returned no row");
        await writeSendCapAudit(tx, {
          workspaceId,
          rawMek,
          actorUserId: ctx.userId,
          action: "send_cap.revoked",
          target: {
            send_cap_id: row.id,
            issuer_user_id: row.issuerUserId,
            grantee_user_id: row.granteeUserId,
          },
          decision: "allow",
          supporting: { reason },
        });
        return { kind: "ok" as const, row };
      });
      if (result.kind === "not_found") {
        return c.json({ error: "not_found", message: "send_cap not found" }, 404);
      }
      if (result.kind === "forbidden") {
        return c.json(
          { error: "forbidden", message: "only the issuer may revoke a send_cap" },
          403,
        );
      }
      return c.json({ send_cap: serializeCap(result.row) });
    } catch (e) {
      const message = e instanceof Error ? e.message : "revoke failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });
};
