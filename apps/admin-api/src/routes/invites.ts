import { writeEvent } from "@getpact/audit";
import { authenticateBearer } from "@getpact/auth";
import { AuthzError, canonicalizeEmail, isUuid, PactError } from "@getpact/core";
import { fromBase64, issueJwt } from "@getpact/crypto";
import {
  assertSafeRuntimeDbRole,
  createClient,
  type Tx,
  UnsafeRuntimeDbRoleError,
  withWorkspace,
} from "@getpact/db";
import { groups, invites, workspaces } from "@getpact/db/schema";
import { loadActiveSigningKey } from "@getpact/keystore";
import { and, eq, inArray, isNull, sql } from "drizzle-orm";
import type { Context, Hono } from "hono";

type InvitesEnv = {
  DATABASE_URL: string;
  MEK: string;
  ISSUER_BASE_URL: string;
  WEB_BASE_URL?: string;
  ENVIRONMENT?: string;
  ADMIN_AUDIENCE?: string;
};

type InvitesAuthContext = {
  workspaceId: string;
  userId: string;
  email: string;
  roles: string[];
};

type AppCtx = Context<{ Bindings: InvitesEnv }>;

const TTL_MIN_SECONDS = 60;
const TTL_MAX_SECONDS = 30 * 24 * 60 * 60;
const INVITE_AUDIENCE = "pact-invite";

const authenticate = async (
  databaseUrl: string,
  workspaceId: string,
  authHeader: string | undefined,
  audience: string,
  issuer: string,
): Promise<InvitesAuthContext> => {
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

const auth = async (c: AppCtx, workspaceId: string): Promise<InvitesAuthContext | Response> => {
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

const isAuth = (v: unknown): v is InvitesAuthContext =>
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

const writeInviteAudit = async (
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
  if (!ws) throw new Error("workspace not found for invite audit");
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

const serializeInvite = (row: {
  id: string;
  email: string;
  scope: unknown;
  ttl: string;
  ttlSeconds: number;
  groupIds: string[];
  expiresAt: Date;
  issuedAt: Date;
  consumedAt: Date | null;
  consumedUserId: string | null;
}) => ({
  id: row.id,
  email: row.email,
  scope: row.scope,
  ttl: row.ttl,
  ttl_seconds: row.ttlSeconds,
  group_ids: row.groupIds,
  issued_at: row.issuedAt.toISOString(),
  expires_at: row.expiresAt.toISOString(),
  consumed_at: row.consumedAt ? row.consumedAt.toISOString() : null,
  consumed_user_id: row.consumedUserId,
});

const inviteWebUrl = (c: AppCtx, token: string): string => {
  const base = c.env.WEB_BASE_URL?.replace(/\/+$/, "") ?? "https://app.getpact.dev";
  return `${base}/invite#${encodeURIComponent(token)}`;
};

type ParsedMint = {
  email: string;
  groupIds: string[];
  scope: Record<string, unknown>;
  ttlSeconds: number;
};

const parseMintBody = (body: unknown): ParsedMint | string => {
  if (!isRecord(body)) return "body must be an object";
  if (typeof body.email !== "string" || body.email.length === 0) {
    return "email is required";
  }
  let scope: Record<string, unknown> = {};
  if (body.scope !== undefined && body.scope !== null) {
    if (!isRecord(body.scope)) return "scope must be an object";
    scope = body.scope;
  }
  let groupIds: string[] = [];
  if (body.group_ids !== undefined && body.group_ids !== null) {
    if (!Array.isArray(body.group_ids)) return "group_ids must be an array";
    for (const g of body.group_ids) {
      if (typeof g !== "string" || !isUuid(g)) return "group_ids must contain uuids";
      groupIds.push(g);
    }
    groupIds = [...new Set(groupIds)];
  }
  if (typeof body.ttl_seconds !== "number" || !Number.isFinite(body.ttl_seconds)) {
    return "ttl_seconds must be a number";
  }
  const ttlSeconds = Math.trunc(body.ttl_seconds);
  if (ttlSeconds < TTL_MIN_SECONDS || ttlSeconds > TTL_MAX_SECONDS) {
    return `ttl_seconds must be between ${TTL_MIN_SECONDS} and ${TTL_MAX_SECONDS}`;
  }
  return { email: canonicalizeEmail(body.email), groupIds, scope, ttlSeconds };
};

export const registerInviteRoutes = <T extends { Bindings: InvitesEnv }>(app: Hono<T>): void => {
  app.post("/v1/workspaces/:workspaceId/invites", async (c) => {
    const workspaceId = requireWorkspaceParam(c as unknown as AppCtx);
    if (typeof workspaceId !== "string") return workspaceId;
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
    if (!isAuth(ctx)) return ctx;

    let raw: unknown;
    try {
      raw = await c.req.json();
    } catch {
      return c.json({ error: "invalid_body", message: "invalid json body" }, 400);
    }
    const parsed = parseMintBody(raw);
    if (typeof parsed === "string") {
      return c.json({ error: "invalid_body", message: parsed }, 400);
    }

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = fromBase64(c.env.MEK);
    const ttlLabel = `${parsed.ttlSeconds}s`;
    try {
      const result = await withWorkspace(db, workspaceId, async (tx) => {
        if (parsed.groupIds.length > 0) {
          const found = await tx
            .select({ id: groups.id })
            .from(groups)
            .where(
              and(
                eq(groups.workspaceId, workspaceId),
                inArray(groups.id, parsed.groupIds),
                isNull(groups.revokedAt),
              ),
            );
          if (found.length !== parsed.groupIds.length) {
            return { kind: "group_missing" as const };
          }
        }

        const jti = crypto.randomUUID();
        const issuedAt = Math.floor(Date.now() / 1000);
        const exp = issuedAt + parsed.ttlSeconds;
        const expiresAt = new Date(exp * 1000);

        const key = await loadActiveSigningKey(tx, workspaceId, "jwt", rawMek);
        const token = await issueJwt(
          {
            sub: `invite:${jti}`,
            email: parsed.email,
            group_ids: parsed.groupIds,
            scope: parsed.scope,
            org: workspaceId,
          },
          {
            privateKey: key.privateKey,
            kid: key.id,
            issuer: c.env.ISSUER_BASE_URL,
            audience: INVITE_AUDIENCE,
            ttlSeconds: parsed.ttlSeconds,
            jti,
          },
        );

        const inserted = await tx
          .insert(invites)
          .values({
            workspaceId,
            jti,
            email: parsed.email,
            groupIds: parsed.groupIds,
            scope: parsed.scope,
            ttl: ttlLabel,
            ttlSeconds: parsed.ttlSeconds,
            issuedAt: new Date(issuedAt * 1000),
            expiresAt,
            createdBy: ctx.userId,
          })
          .returning();
        const row = inserted[0];
        if (!row) throw new Error("invite insert returned no row");

        await writeInviteAudit(tx, {
          workspaceId,
          rawMek,
          actorUserId: ctx.userId,
          action: "invite.created",
          target: { invite_id: row.id, jti, email: parsed.email, group_ids: parsed.groupIds },
          decision: "allow",
          supporting: { ttl_seconds: parsed.ttlSeconds },
        });

        return { kind: "ok" as const, row, token };
      });
      if (result.kind === "group_missing") {
        return c.json({ error: "not_found", message: "one or more groups not found" }, 404);
      }
      return c.json(
        {
          invite_id: result.row.id,
          token: result.token,
          accept_url: inviteWebUrl(c as unknown as AppCtx, result.token),
          invite: serializeInvite(result.row),
        },
        201,
      );
    } catch (e) {
      const message = e instanceof Error ? e.message : "mint failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });

  app.get("/v1/workspaces/:workspaceId/invites", async (c) => {
    const workspaceId = requireWorkspaceParam(c as unknown as AppCtx);
    if (typeof workspaceId !== "string") return workspaceId;
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
    if (!isAuth(ctx)) return ctx;

    const db = createClient(c.env.DATABASE_URL);
    try {
      const rows = await withWorkspace(db, workspaceId, (tx) =>
        tx
          .select()
          .from(invites)
          .where(eq(invites.workspaceId, workspaceId))
          .orderBy(sql`${invites.createdAt} DESC`),
      );
      return c.json({ invites: rows.map(serializeInvite) });
    } catch (e) {
      const message = e instanceof Error ? e.message : "list failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });

  app.post("/v1/workspaces/:workspaceId/invites/:id/revoke", async (c) => {
    const workspaceId = requireWorkspaceParam(c as unknown as AppCtx);
    if (typeof workspaceId !== "string") return workspaceId;
    const id = c.req.param("id");
    if (!id || !isUuid(id)) {
      return c.json({ error: "invalid_request", message: "invite id must be a uuid" }, 400);
    }
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
    if (!isAuth(ctx)) return ctx;

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = fromBase64(c.env.MEK);
    try {
      const result = await withWorkspace(db, workspaceId, async (tx) => {
        const updated = await tx
          .update(invites)
          .set({ consumedAt: new Date(), status: "revoked" })
          .where(
            and(
              eq(invites.workspaceId, workspaceId),
              eq(invites.id, id),
              isNull(invites.consumedAt),
            ),
          )
          .returning();
        const row = updated[0];
        if (!row) return { kind: "not_found" as const };
        await writeInviteAudit(tx, {
          workspaceId,
          rawMek,
          actorUserId: ctx.userId,
          action: "invite.revoked",
          target: { invite_id: row.id, jti: row.jti, email: row.email },
          decision: "allow",
        });
        return { kind: "ok" as const, row };
      });
      if (result.kind === "not_found") {
        return c.json({ error: "not_found", message: "invite not found or already consumed" }, 404);
      }
      return c.json({ invite: serializeInvite(result.row) });
    } catch (e) {
      const message = e instanceof Error ? e.message : "revoke failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });
};
