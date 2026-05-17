import { writeEvent } from "@getpact/audit";
import { authenticateBearer } from "@getpact/auth";
import { AuthzError, isUuid, PactError } from "@getpact/core";
import { type Ed25519PublicJwk, fromBase64, sdjwt } from "@getpact/crypto";
import {
  assertSafeRuntimeDbRole,
  createClient,
  type Tx,
  UnsafeRuntimeDbRoleError,
  withWorkspace,
} from "@getpact/db";
import {
  agentCapabilityGrants,
  agents,
  users,
  workspaceAudiences,
  workspaces,
} from "@getpact/db/schema";
import { loadActiveSigningKey } from "@getpact/keystore";
import { and, asc, eq, isNull } from "drizzle-orm";
import type { Context, Hono } from "hono";

type AgentsEnv = {
  DATABASE_URL: string;
  MEK: string;
  ISSUER_BASE_URL: string;
  ENVIRONMENT?: string;
  ADMIN_AUDIENCE?: string;
};

type AgentsAuthContext = {
  workspaceId: string;
  userId: string;
  email: string;
  roles: string[];
};

type AppCtx = Context<{ Bindings: AgentsEnv }>;

const NAME_MAX = 80;
const DESCRIPTION_MAX = 280;
const TOOL_NAME_MAX = 120;
const MAX_USES_MIN = 1;
const MAX_USES_MAX = 1_000_000;
const DEFAULT_MAX_USES = 1000;

const authenticate = async (
  databaseUrl: string,
  workspaceId: string,
  authHeader: string | undefined,
  audience: string,
  issuer: string,
): Promise<AgentsAuthContext> => {
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

const auth = async (c: AppCtx, workspaceId: string): Promise<AgentsAuthContext | Response> => {
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

const isAuth = (v: unknown): v is AgentsAuthContext =>
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

const writeAgentAudit = async (
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
  if (!ws) throw new Error("workspace not found for agent audit");
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

const isUniqueViolation = (err: unknown): boolean =>
  !!err && typeof err === "object" && "code" in err && (err as { code?: unknown }).code === "23505";

const slugify = (raw: string): string => {
  const base = raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (base.length === 0) return "agent";
  return base.slice(0, 48);
};

const isEd25519PublicJwk = (value: unknown): value is Ed25519PublicJwk => {
  if (!isRecord(value)) return false;
  return value.kty === "OKP" && value.crv === "Ed25519" && typeof value.x === "string";
};

const serializeAgent = (row: {
  id: string;
  name?: string;
  displayName?: string;
  slug: string;
  ownerUserId: string;
  status: string;
  createdAt: Date;
  revokedAt: Date | null;
}) => ({
  id: row.id,
  name: row.displayName ?? row.slug,
  slug: row.slug,
  status: row.status,
  owner_user_id: row.ownerUserId,
  created_at: row.createdAt.toISOString(),
  revoked_at: row.revokedAt ? row.revokedAt.toISOString() : null,
});

const serializeGrant = (row: {
  id: string;
  agentId: string;
  toolName: string;
  audience: string[];
  scope: unknown;
  maxUsesPerDay: number;
  onBehalfOfUserId: string | null;
  onBehalfOfPattern: string | null;
  createdAt: Date;
  revokedAt: Date | null;
  expiresAt: Date | null;
}) => ({
  id: row.id,
  agent_id: row.agentId,
  tool_name: row.toolName,
  audience: row.audience,
  scope: row.scope,
  max_per_day: row.maxUsesPerDay,
  on_behalf_of_user_id: row.onBehalfOfUserId,
  on_behalf_of_pattern: row.onBehalfOfPattern,
  created_at: row.createdAt.toISOString(),
  revoked_at: row.revokedAt ? row.revokedAt.toISOString() : null,
  expires_at: row.expiresAt ? row.expiresAt.toISOString() : null,
});

type CreateAgentBody = {
  name?: unknown;
  description?: unknown;
  owner_user_id?: unknown;
  pubkey_jwk?: unknown;
  kind?: unknown;
};

type ParsedAgent = {
  name: string;
  slug: string;
  ownerUserId: string;
  pubkeyJwk: Ed25519PublicJwk;
  kind: "service" | "user_delegated" | "sub_agent";
};

const parseCreateAgentBody = (body: CreateAgentBody): ParsedAgent | string => {
  if (typeof body.name !== "string" || body.name.length === 0 || body.name.length > NAME_MAX) {
    return "name is required";
  }
  if (typeof body.owner_user_id !== "string" || !isUuid(body.owner_user_id)) {
    return "owner_user_id must be a uuid";
  }
  if (body.description !== undefined && body.description !== null) {
    if (typeof body.description !== "string" || body.description.length > DESCRIPTION_MAX) {
      return "description must be a string up to 280 characters";
    }
  }
  if (!isEd25519PublicJwk(body.pubkey_jwk)) {
    return "pubkey_jwk must be an Ed25519 OKP public JWK";
  }
  let kind: "service" | "user_delegated" | "sub_agent" = "service";
  if (body.kind !== undefined && body.kind !== null) {
    if (body.kind !== "service" && body.kind !== "user_delegated" && body.kind !== "sub_agent") {
      return "kind must be one of service, user_delegated, sub_agent";
    }
    kind = body.kind;
  }
  return {
    name: body.name,
    slug: slugify(body.name),
    ownerUserId: body.owner_user_id,
    pubkeyJwk: body.pubkey_jwk,
    kind,
  };
};

type CreateGrantBody = {
  tool_name?: unknown;
  audience?: unknown;
  scope?: unknown;
  max_per_day?: unknown;
  expires_at?: unknown;
  on_behalf_of_user_id?: unknown;
  on_behalf_of_pattern?: unknown;
};

type ParsedGrant = {
  toolName: string;
  audience: string;
  scope: Record<string, unknown>;
  maxUsesPerDay: number;
  onBehalfOfUserId: string | null;
  onBehalfOfPattern: string | null;
  expiresAt: Date | null;
};

const parseCreateGrantBody = (body: CreateGrantBody): ParsedGrant | string => {
  if (
    typeof body.tool_name !== "string" ||
    body.tool_name.length === 0 ||
    body.tool_name.length > TOOL_NAME_MAX
  ) {
    return "tool_name is required";
  }
  if (typeof body.audience !== "string" || body.audience.length === 0) {
    return "audience is required";
  }
  if (!isRecord(body.scope)) {
    return "scope must be a JSON object";
  }
  let maxUsesPerDay = DEFAULT_MAX_USES;
  if (body.max_per_day !== undefined && body.max_per_day !== null) {
    if (typeof body.max_per_day !== "number" || !Number.isFinite(body.max_per_day)) {
      return "max_per_day must be a positive integer";
    }
    const n = Math.trunc(body.max_per_day);
    if (n < MAX_USES_MIN || n > MAX_USES_MAX) {
      return `max_per_day must be between ${MAX_USES_MIN} and ${MAX_USES_MAX}`;
    }
    maxUsesPerDay = n;
  }
  let expiresAt: Date | null = null;
  if (body.expires_at !== undefined && body.expires_at !== null) {
    if (typeof body.expires_at !== "string") return "expires_at must be an ISO string";
    const parsed = new Date(body.expires_at);
    if (Number.isNaN(parsed.valueOf())) return "expires_at is not a valid date";
    if (parsed.getTime() <= Date.now()) return "expires_at must be in the future";
    expiresAt = parsed;
  }
  let onBehalfOfUserId: string | null = null;
  let onBehalfOfPattern: string | null = null;
  if (body.on_behalf_of_user_id !== undefined && body.on_behalf_of_user_id !== null) {
    if (typeof body.on_behalf_of_user_id !== "string" || !isUuid(body.on_behalf_of_user_id)) {
      return "on_behalf_of_user_id must be a uuid";
    }
    onBehalfOfUserId = body.on_behalf_of_user_id;
  }
  if (body.on_behalf_of_pattern !== undefined && body.on_behalf_of_pattern !== null) {
    if (typeof body.on_behalf_of_pattern !== "string" || body.on_behalf_of_pattern.length === 0) {
      return "on_behalf_of_pattern must be a non-empty string";
    }
    onBehalfOfPattern = body.on_behalf_of_pattern;
  }
  if (!onBehalfOfUserId && !onBehalfOfPattern) {
    return "either on_behalf_of_user_id or on_behalf_of_pattern is required";
  }
  return {
    toolName: body.tool_name,
    audience: body.audience,
    scope: body.scope,
    maxUsesPerDay,
    onBehalfOfUserId,
    onBehalfOfPattern,
    expiresAt,
  };
};

const lookupAudience = async (
  tx: Tx,
  workspaceId: string,
  name: string,
): Promise<{ id: string } | null> => {
  const rows = await tx
    .select({ id: workspaceAudiences.id })
    .from(workspaceAudiences)
    .where(
      and(
        eq(workspaceAudiences.workspaceId, workspaceId),
        eq(workspaceAudiences.name, name),
        isNull(workspaceAudiences.revokedAt),
      ),
    )
    .limit(1);
  return rows[0] ?? null;
};

export const registerAgentRoutes = <T extends { Bindings: AgentsEnv }>(app: Hono<T>): void => {
  app.post("/v1/workspaces/:workspaceId/agents", async (c) => {
    const workspaceId = requireWorkspaceParam(c as unknown as AppCtx);
    if (typeof workspaceId !== "string") return workspaceId;
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
    if (!isAuth(ctx)) return ctx;

    let body: CreateAgentBody;
    try {
      body = (await c.req.json()) as CreateAgentBody;
    } catch {
      return c.json({ error: "invalid_body", message: "invalid json body" }, 400);
    }
    if (!isRecord(body)) {
      return c.json({ error: "invalid_body", message: "body must be an object" }, 400);
    }
    const parsed = parseCreateAgentBody(body);
    if (typeof parsed === "string") {
      return c.json({ error: "invalid_body", message: parsed }, 400);
    }

    let thumbprint: string;
    try {
      thumbprint = await sdjwt.jwkThumbprint(parsed.pubkeyJwk);
    } catch {
      return c.json({ error: "invalid_body", message: "pubkey_jwk thumbprint failed" }, 400);
    }

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = fromBase64(c.env.MEK);
    try {
      const result = await withWorkspace(db, workspaceId, async (tx) => {
        const [owner] = await tx
          .select({ id: users.id })
          .from(users)
          .where(and(eq(users.workspaceId, workspaceId), eq(users.id, parsed.ownerUserId)))
          .limit(1);
        if (!owner) return { kind: "owner_not_found" as const };

        const rows = await tx
          .insert(agents)
          .values({
            workspaceId,
            slug: parsed.slug,
            displayName: parsed.name,
            kind: parsed.kind,
            ownerUserId: parsed.ownerUserId,
            pubkeyJwk: parsed.pubkeyJwk,
            pubkeyThumbprint: thumbprint,
          })
          .returning();
        const row = rows[0];
        if (!row) throw new Error("agent insert returned no row");
        await writeAgentAudit(tx, {
          workspaceId,
          rawMek,
          actorUserId: ctx.userId,
          action: "admin.agent.created",
          target: { agent_id: row.id, slug: row.slug, owner_user_id: row.ownerUserId },
          decision: "allow",
          supporting: { kind: row.kind, pubkey_thumbprint: row.pubkeyThumbprint },
        });
        return { kind: "ok" as const, row };
      });
      if (result.kind === "owner_not_found") {
        return c.json({ error: "not_found", message: "owner_user_id not found" }, 404);
      }
      return c.json({ agent: serializeAgent(result.row) }, 201);
    } catch (e) {
      if (isUniqueViolation(e)) {
        return c.json({ error: "conflict", message: "agent slug or pubkey already exists" }, 409);
      }
      const message = e instanceof Error ? e.message : "create failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });

  app.get("/v1/workspaces/:workspaceId/agents", async (c) => {
    const workspaceId = requireWorkspaceParam(c as unknown as AppCtx);
    if (typeof workspaceId !== "string") return workspaceId;
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
    if (!isAuth(ctx)) return ctx;

    const db = createClient(c.env.DATABASE_URL);
    try {
      const rows = await withWorkspace(db, workspaceId, (tx) =>
        tx
          .select()
          .from(agents)
          .where(and(eq(agents.workspaceId, workspaceId), isNull(agents.revokedAt)))
          .orderBy(asc(agents.createdAt)),
      );
      return c.json({ agents: rows.map(serializeAgent) });
    } catch (e) {
      const message = e instanceof Error ? e.message : "list failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });

  app.post("/v1/workspaces/:workspaceId/agents/:agentId/grants", async (c) => {
    const workspaceId = requireWorkspaceParam(c as unknown as AppCtx);
    if (typeof workspaceId !== "string") return workspaceId;
    const agentId = c.req.param("agentId");
    if (!agentId || !isUuid(agentId)) {
      return c.json({ error: "invalid_request", message: "agent id must be a uuid" }, 400);
    }
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
    if (!isAuth(ctx)) return ctx;

    let body: CreateGrantBody;
    try {
      body = (await c.req.json()) as CreateGrantBody;
    } catch {
      return c.json({ error: "invalid_body", message: "invalid json body" }, 400);
    }
    if (!isRecord(body)) {
      return c.json({ error: "invalid_body", message: "body must be an object" }, 400);
    }
    const parsed = parseCreateGrantBody(body);
    if (typeof parsed === "string") {
      return c.json({ error: "invalid_body", message: parsed }, 400);
    }

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = fromBase64(c.env.MEK);
    try {
      const result = await withWorkspace(db, workspaceId, async (tx) => {
        const [agent] = await tx
          .select({ id: agents.id })
          .from(agents)
          .where(and(eq(agents.workspaceId, workspaceId), eq(agents.id, agentId)))
          .limit(1);
        if (!agent) return { kind: "agent_not_found" as const };

        const audienceRow = await lookupAudience(tx, workspaceId, parsed.audience);
        if (!audienceRow) {
          return { kind: "unknown_audience" as const };
        }

        if (parsed.onBehalfOfUserId) {
          const [subject] = await tx
            .select({ id: users.id })
            .from(users)
            .where(and(eq(users.workspaceId, workspaceId), eq(users.id, parsed.onBehalfOfUserId)))
            .limit(1);
          if (!subject) return { kind: "subject_not_found" as const };
        }

        const rows = await tx
          .insert(agentCapabilityGrants)
          .values({
            workspaceId,
            agentId,
            toolName: parsed.toolName,
            scope: parsed.scope,
            audience: [parsed.audience],
            maxUsesPerDay: parsed.maxUsesPerDay,
            onBehalfOfUserId: parsed.onBehalfOfUserId,
            onBehalfOfPattern: parsed.onBehalfOfPattern,
            expiresAt: parsed.expiresAt,
            createdByUserId: ctx.userId,
          })
          .returning();
        const row = rows[0];
        if (!row) throw new Error("grant insert returned no row");
        await writeAgentAudit(tx, {
          workspaceId,
          rawMek,
          actorUserId: ctx.userId,
          action: "admin.agent.grant.created",
          target: {
            agent_id: agentId,
            grant_id: row.id,
            tool_name: row.toolName,
            audience: row.audience,
          },
          decision: "allow",
          supporting: {
            max_uses_per_day: row.maxUsesPerDay,
            on_behalf_of_user_id: row.onBehalfOfUserId,
            on_behalf_of_pattern: row.onBehalfOfPattern,
          },
        });
        return { kind: "ok" as const, row };
      });
      if (result.kind === "agent_not_found") {
        return c.json({ error: "not_found", message: "agent not found" }, 404);
      }
      if (result.kind === "subject_not_found") {
        return c.json({ error: "not_found", message: "on_behalf_of_user_id not found" }, 404);
      }
      if (result.kind === "unknown_audience") {
        return c.json(
          { error: "unknown_audience", message: "audience is not registered for workspace" },
          400,
        );
      }
      return c.json({ grant: serializeGrant(result.row) }, 201);
    } catch (e) {
      const message = e instanceof Error ? e.message : "create failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });

  app.delete("/v1/workspaces/:workspaceId/agents/:agentId/grants/:grantId", async (c) => {
    const workspaceId = requireWorkspaceParam(c as unknown as AppCtx);
    if (typeof workspaceId !== "string") return workspaceId;
    const agentId = c.req.param("agentId");
    const grantId = c.req.param("grantId");
    if (!agentId || !isUuid(agentId) || !grantId || !isUuid(grantId)) {
      return c.json(
        { error: "invalid_request", message: "agent id and grant id must be uuids" },
        400,
      );
    }
    const ctx = await auth(c as unknown as AppCtx, workspaceId);
    if (!isAuth(ctx)) return ctx;

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = fromBase64(c.env.MEK);
    try {
      const outcome = await withWorkspace(db, workspaceId, async (tx) => {
        const [existing] = await tx
          .select()
          .from(agentCapabilityGrants)
          .where(
            and(
              eq(agentCapabilityGrants.workspaceId, workspaceId),
              eq(agentCapabilityGrants.agentId, agentId),
              eq(agentCapabilityGrants.id, grantId),
            ),
          )
          .limit(1);
        if (!existing) return { kind: "not_found" as const };
        if (existing.revokedAt) {
          return { kind: "idempotent" as const, row: existing };
        }
        const updated = await tx
          .update(agentCapabilityGrants)
          .set({ revokedAt: new Date() })
          .where(
            and(
              eq(agentCapabilityGrants.workspaceId, workspaceId),
              eq(agentCapabilityGrants.id, grantId),
            ),
          )
          .returning();
        const row = updated[0];
        if (!row) throw new Error("grant revoke returned no row");
        await writeAgentAudit(tx, {
          workspaceId,
          rawMek,
          actorUserId: ctx.userId,
          action: "admin.agent.grant.revoked",
          target: { agent_id: agentId, grant_id: grantId, tool_name: row.toolName },
          decision: "allow",
        });
        return { kind: "ok" as const, row };
      });
      if (outcome.kind === "not_found") {
        return c.json({ error: "not_found", message: "grant not found" }, 404);
      }
      if (outcome.kind === "idempotent") {
        return c.json({ grant: serializeGrant(outcome.row), idempotent: true });
      }
      return c.json({ grant: serializeGrant(outcome.row) });
    } catch (e) {
      const message = e instanceof Error ? e.message : "revoke failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });
};
