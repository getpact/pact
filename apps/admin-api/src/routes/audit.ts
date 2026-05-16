import { authenticateBearer } from "@getpact/auth";
import { AuthzError, PactError } from "@getpact/core";
import {
  assertSafeRuntimeDbRole,
  createClient,
  type Tx,
  UnsafeRuntimeDbRoleError,
  withWorkspace,
} from "@getpact/db";
import { auditChainState, auditEvents, workspaces } from "@getpact/db/schema";
import { and, asc, desc, eq, gt, gte, lt, lte } from "drizzle-orm";
import type { Context, Hono } from "hono";

type AuditEnv = {
  DATABASE_URL: string;
  ISSUER_BASE_URL: string;
  ENVIRONMENT?: string;
  ADMIN_AUDIENCE?: string;
  AUDIT_AUDIENCE?: string;
};

type AuditAuthContext = {
  workspaceId: string;
  userId: string;
  email: string;
  roles: string[];
};

type QueryOrder = "asc" | "desc";

type QueryInput = {
  workspaceId: string;
  action?: string;
  since?: Date;
  until?: Date;
  limit: number;
  order?: QueryOrder;
  cursor?: { auditSeq: number };
};

export type AuditQueryRow = {
  id: string;
  workspaceId: string;
  auditSeq: number;
  ts: Date;
  actorKind: string;
  actorId: string | null;
  action: string;
  target: unknown;
  decision: string;
  supporting: unknown;
  signingKeyId: string;
  prevHash: string;
  thisHash: string;
  signature: string;
};

type QueryOutput = {
  events: AuditQueryRow[];
  nextCursor: string | null;
};

const MAX_LIMIT = 200;
const DEFAULT_LIMIT = 50;

export const parseCursor = (raw: string | undefined): QueryInput["cursor"] => {
  if (!raw) return undefined;
  if (!/^[1-9]\d*$/.test(raw)) return undefined;
  const auditSeq = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(auditSeq)) return undefined;
  return { auditSeq };
};

export const formatCursor = (row: AuditQueryRow): string => String(row.auditSeq);

const queryEvents = async (tx: Tx, input: QueryInput): Promise<QueryOutput> => {
  const conditions = [eq(auditEvents.workspaceId, input.workspaceId)];
  if (input.action) conditions.push(eq(auditEvents.action, input.action));
  if (input.since) conditions.push(gte(auditEvents.ts, input.since));
  if (input.until) conditions.push(lte(auditEvents.ts, input.until));
  const order = input.order ?? "desc";
  if (input.cursor) {
    conditions.push(
      order === "asc"
        ? gt(auditEvents.auditSeq, input.cursor.auditSeq)
        : lt(auditEvents.auditSeq, input.cursor.auditSeq),
    );
  }

  const orderClauses = order === "asc" ? [asc(auditEvents.auditSeq)] : [desc(auditEvents.auditSeq)];

  const rows = await tx
    .select()
    .from(auditEvents)
    .where(and(...conditions))
    .orderBy(...orderClauses)
    .limit(input.limit + 1);

  const hasMore = rows.length > input.limit;
  const trimmed = hasMore ? rows.slice(0, input.limit) : rows;
  const last = trimmed[trimmed.length - 1];

  return {
    events: trimmed.map((r) => ({
      id: r.id,
      workspaceId: r.workspaceId,
      auditSeq: r.auditSeq,
      ts: r.ts,
      actorKind: r.actorKind,
      actorId: r.actorId,
      action: r.action,
      target: r.target,
      decision: r.decision,
      supporting: r.supporting,
      signingKeyId: r.signingKeyId,
      prevHash: r.prevHash,
      thisHash: r.thisHash,
      signature: r.signature,
    })),
    nextCursor: hasMore && last ? formatCursor(last) : null,
  };
};

const authenticateAuditReader = async (
  databaseUrl: string,
  workspaceId: string,
  authHeader: string | undefined,
  audiences: string[],
  issuer: string,
): Promise<AuditAuthContext> => {
  let lastError: unknown;
  for (const audience of audiences) {
    try {
      const { claims } = await authenticateBearer({
        databaseUrl,
        authHeader,
        audience,
        issuer,
        expectedWorkspaceId: workspaceId,
      });
      if (!claims.roles.includes("admin") && !claims.roles.includes("auditor")) {
        throw new AuthzError("admin or auditor role required");
      }
      return {
        workspaceId: claims.workspaceId,
        userId: claims.userId,
        email: claims.email,
        roles: claims.roles,
      };
    } catch (e) {
      lastError = e;
      if (e instanceof AuthzError) throw e;
    }
  }
  if (lastError instanceof Error) throw lastError;
  throw new Error("audit auth failed");
};

type AppCtx = Context<{ Bindings: AuditEnv }>;

const auth = async (c: AppCtx, workspaceId: string): Promise<AuditAuthContext | Response> => {
  const audiences = [c.env.AUDIT_AUDIENCE ?? "pact-audit", c.env.ADMIN_AUDIENCE ?? "pact-admin"];
  try {
    await assertSafeRuntimeDbRole(c.env.DATABASE_URL, {
      production: c.env.ENVIRONMENT === "production",
    });
    return await authenticateAuditReader(
      c.env.DATABASE_URL,
      workspaceId,
      c.req.header("Authorization"),
      audiences,
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

const isAuth = (v: unknown): v is AuditAuthContext =>
  typeof v === "object" && v !== null && "userId" in v;

export const registerAuditRoutes = <T extends { Bindings: AuditEnv }>(app: Hono<T>): void => {
  app.get("/v1/workspaces/:id/audit/events", async (c) => {
    const workspaceId = c.req.param("id");
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
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

  app.get("/v1/workspaces/:id/audit/workspace", async (c) => {
    const workspaceId = c.req.param("id");
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
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
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
    if (!isAuth(ctx)) return ctx;

    const db = createClient(c.env.DATABASE_URL);
    const [head] = await withWorkspace(db, workspaceId, (tx) =>
      tx
        .select()
        .from(auditChainState)
        .where(eq(auditChainState.workspaceId, workspaceId))
        .limit(1),
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
};
