import { writeEvent } from "@getpact/audit";
import { authenticateBearer, type BearerClaims } from "@getpact/auth";
import { canonicalizeEmail, isUuid } from "@getpact/core";
import { sdjwt, validateCnfJwk } from "@getpact/crypto";
import type { Tx } from "@getpact/db";
import { createClient, withWorkspace } from "@getpact/db";
import { revokedJtis, workspaceAudiences, workspaces } from "@getpact/db/schema";
import { loadActiveSigningKey } from "@getpact/keystore";
import type { MetricsClient, SentryClient } from "@getpact/logger";
import { databaseRateLimiter, memoryRateLimiter, type RateLimiter } from "@getpact/ratelimit";
import { and, eq, isNull, sql } from "drizzle-orm";
import type { Context, Hono } from "hono";
import { decodeMek, type Env } from "../env.js";

type AppVariables = {
  sentry: SentryClient;
  metrics: MetricsClient;
};
type IssuerApp = Hono<{ Bindings: Env; Variables: AppVariables }>;
type IssuerCtx = Context<{ Bindings: Env; Variables: AppVariables }>;

type MintBody = {
  on_behalf_of?: unknown;
  tool_name?: unknown;
  scope?: unknown;
  ttl_seconds?: unknown;
  max_redeems?: unknown;
  audience?: unknown;
  intent_jti?: unknown;
  cnf_jwk?: unknown;
};

type RevokeBody = {
  cascade?: unknown;
  reason?: unknown;
};

type ParsedMint = {
  onBehalfOf: string;
  toolName: string;
  scope: Record<string, unknown>;
  ttlSeconds: number;
  maxRedeems: number;
  audience: string;
  intentJti: string | null;
  cnfJwk: Record<string, unknown>;
};

const TTL_MIN = 30;
const TTL_MAX = 3600;
const TTL_DEFAULT = 300;
const REDEEM_MIN = 1;
const REDEEM_MAX = 100;
const REDEEM_DEFAULT = 1;
const REASON_MAX = 280;
const CASCADE_MAX = 1024;
const RATE_LIMIT_PER_MIN = 100;

const memLimiter = memoryRateLimiter();
const testLimiter: RateLimiter = {
  async hit(_key, limit) {
    return { allowed: true, remaining: limit, resetAt: Date.now() + 60_000 };
  },
};

const pickLimiter = (env: Env): RateLimiter =>
  env.ENVIRONMENT === "production"
    ? databaseRateLimiter(env.DATABASE_URL)
    : env.ENVIRONMENT === "test"
      ? testLimiter
      : memLimiter;

const clampInt = (value: unknown, fallback: number, min: number, max: number): number => {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  const v = Math.trunc(value);
  if (v < min) return min;
  if (v > max) return max;
  return v;
};

const parseMintBody = (body: MintBody): ParsedMint | string => {
  if (typeof body.on_behalf_of !== "string" || body.on_behalf_of.length === 0) {
    return "on_behalf_of is required";
  }
  if (typeof body.tool_name !== "string" || body.tool_name.length === 0) {
    return "tool_name is required";
  }
  if (typeof body.audience !== "string" || body.audience.length === 0) {
    return "audience is required";
  }
  if (!body.scope || typeof body.scope !== "object" || Array.isArray(body.scope)) {
    return "scope must be an object";
  }
  let intentJti: string | null = null;
  if (body.intent_jti !== undefined) {
    if (typeof body.intent_jti !== "string") return "intent_jti must be a string";
    intentJti = body.intent_jti;
  }
  const validatedCnf = validateCnfJwk(body.cnf_jwk);
  if ("error" in validatedCnf) {
    return validatedCnf.error;
  }
  const cnfJwk = validatedCnf as unknown as Record<string, unknown>;
  return {
    onBehalfOf: body.on_behalf_of,
    toolName: body.tool_name,
    scope: body.scope as Record<string, unknown>,
    ttlSeconds: clampInt(body.ttl_seconds, TTL_DEFAULT, TTL_MIN, TTL_MAX),
    maxRedeems: clampInt(body.max_redeems, REDEEM_DEFAULT, REDEEM_MIN, REDEEM_MAX),
    audience: body.audience,
    intentJti,
    cnfJwk,
  };
};

const resolveOnBehalfOf = async (
  tx: Tx,
  workspaceId: string,
  raw: string,
): Promise<{ id: string; email: string } | null> => {
  if (isUuid(raw)) {
    const rows = (await tx.execute(
      sql`SELECT id, email FROM users WHERE workspace_id = ${workspaceId} AND id = ${raw} LIMIT 1`,
    )) as Array<{ id: string; email: string }>;
    return rows[0] ?? null;
  }
  const email = canonicalizeEmail(raw);
  const rows = (await tx.execute(
    sql`SELECT id, email FROM users WHERE workspace_id = ${workspaceId} AND email = ${email} LIMIT 1`,
  )) as Array<{ id: string; email: string }>;
  return rows[0] ?? null;
};

type GrantRow = {
  id: string;
  agent_id: string;
  on_behalf_of_user_id: string | null;
  on_behalf_of_pattern: string | null;
  max_uses_per_day: number;
  scope: unknown;
  created_by_user_id: string;
  audience: string[];
  expires_at: Date | string | null;
};

const loadAgent = async (
  tx: Tx,
  workspaceId: string,
  agentId: string,
): Promise<{ id: string; status: string } | null> => {
  if (!isUuid(agentId)) return null;
  const rows = (await tx.execute(
    sql`SELECT id, status FROM agents WHERE workspace_id = ${workspaceId} AND id = ${agentId} LIMIT 1`,
  )) as Array<{ id: string; status: string }>;
  return rows[0] ?? null;
};

const findGrant = async (
  tx: Tx,
  input: {
    workspaceId: string;
    agentId: string;
    toolName: string;
    audience: string;
    userId: string;
    userEmail: string;
    scope: Record<string, unknown>;
  },
): Promise<GrantRow | null> => {
  const scopeJson = JSON.stringify(input.scope);
  const rows = (await tx.execute(
    sql`SELECT id, agent_id, on_behalf_of_user_id, on_behalf_of_pattern, max_uses_per_day, scope, created_by_user_id, audience, expires_at
        FROM agent_capability_grants
        WHERE workspace_id = ${input.workspaceId}
          AND agent_id = ${input.agentId}
          AND tool_name = ${input.toolName}
          AND revoked_at IS NULL
          AND scope @> ${scopeJson}::jsonb
          AND (
            on_behalf_of_user_id = ${input.userId}::uuid
            OR (on_behalf_of_pattern IS NOT NULL AND ${input.userEmail} LIKE on_behalf_of_pattern)
          )
          AND (
            cardinality(audience) = 0
            OR ${input.audience} = ANY(audience)
          )
        ORDER BY created_at DESC
        LIMIT 1
        FOR UPDATE`,
  )) as Array<GrantRow>;
  return rows[0] ?? null;
};

// Postgres forbids FOR UPDATE with aggregates. The caller already takes a
// row-level lock on the grant in findGrant; that lock serializes mints for
// this grant, so the count below does not need its own FOR UPDATE.
export const countRecentInvocations = async (
  tx: Tx,
  workspaceId: string,
  grantId: string,
): Promise<number> => {
  const rows = (await tx.execute(
    sql`SELECT count(*)::int AS n
        FROM agent_invocations
        WHERE workspace_id = ${workspaceId}
          AND grant_id = ${grantId}
          AND issued_at > NOW() - INTERVAL '24 hours'`,
  )) as Array<{ n: number | string }>;
  return Number(rows[0]?.n ?? 0);
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

const adminAuth = async (c: IssuerCtx, workspaceId: string): Promise<BearerClaims | Response> => {
  try {
    const { claims } = await authenticateBearer({
      databaseUrl: c.env.DATABASE_URL,
      authHeader: c.req.header("Authorization"),
      audience: "pact-admin",
      issuer: c.env.ISSUER_BASE_URL,
      expectedWorkspaceId: workspaceId,
    });
    if (!claims.roles.includes("admin")) {
      return c.json({ error: "forbidden", message: "admin role required" }, 403);
    }
    return claims;
  } catch (e) {
    const message = e instanceof Error ? e.message : "auth failed";
    return c.json({ error: "unauthorized", message }, 401);
  }
};

const findWorkspaceIdForJti = async (databaseUrl: string, jti: string): Promise<string | null> => {
  if (!isUuid(jti)) return null;
  const db = createClient(databaseUrl);
  const rows = (await db.execute(
    sql`SELECT workspace_id FROM agent_invocations WHERE jti = ${jti} LIMIT 1`,
  )) as Array<{ workspace_id: string }>;
  return rows[0]?.workspace_id ?? null;
};

const isRecordObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const AGENT_STATUSES = new Set(["active", "suspended", "revoked"]);
const LIST_LIMIT_DEFAULT = 50;
const LIST_LIMIT_MAX = 200;

const subjectMatchesPattern = (subject: string, pattern: string): boolean => {
  if (pattern.length === 0) return false;
  if (pattern.startsWith("@")) {
    const at = subject.lastIndexOf("@");
    if (at < 0) return false;
    return subject.slice(at) === pattern;
  }
  return subject === pattern;
};

const subjectAllowedByPatterns = (subject: string, patterns: string[]): boolean => {
  if (patterns.length === 0) return true;
  return patterns.some((p) => subjectMatchesPattern(subject, p));
};

const lookupAudience = async (
  tx: Tx,
  workspaceId: string,
  name: string,
): Promise<{ id: string; allowedSubjectPatterns: string[] } | null> => {
  const rows = await tx
    .select({
      id: workspaceAudiences.id,
      allowedSubjectPatterns: workspaceAudiences.allowedSubjectPatterns,
    })
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

type AgentListRow = {
  id: string;
  slug: string;
  display_name: string;
  kind: string;
  owner_user_id: string;
  status: string;
  created_at: Date | string;
};

export const registerAgentRoutes = (app: IssuerApp): void => {
  app.get("/v1/agents", async (c) => {
    const workspaceId = c.req.query("workspace_id");
    if (!workspaceId || !isUuid(workspaceId)) {
      return c.json({ error: "invalid_query", message: "workspace_id is required" }, 400);
    }
    const status = c.req.query("status");
    if (status !== undefined && !AGENT_STATUSES.has(status)) {
      return c.json(
        { error: "invalid_query", message: "status must be active, suspended, or revoked" },
        400,
      );
    }
    let limit = LIST_LIMIT_DEFAULT;
    const limitRaw = c.req.query("limit");
    if (limitRaw !== undefined) {
      const n = Number.parseInt(limitRaw, 10);
      if (!Number.isFinite(n) || n <= 0) {
        return c.json({ error: "invalid_query", message: "limit must be a positive integer" }, 400);
      }
      limit = Math.min(n, LIST_LIMIT_MAX);
    }

    const ctx = await adminAuth(c, workspaceId);
    if (ctx instanceof Response) return ctx;

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = decodeMek(c.env);
    try {
      const rows = await withWorkspace(db, workspaceId, async (tx) => {
        const statusClause = status ? sql`AND status = ${status}` : sql``;
        const result = (await tx.execute(
          sql`SELECT id, slug, display_name, kind, owner_user_id, status, created_at
              FROM agents
              WHERE workspace_id = ${workspaceId}
              ${statusClause}
              ORDER BY created_at DESC
              LIMIT ${limit}`,
        )) as Array<AgentListRow>;
        await writeAgentAudit(tx, {
          workspaceId,
          rawMek,
          actorUserId: ctx.userId,
          action: "agent.list",
          target: { workspace_id: workspaceId, status: status ?? null, limit },
          decision: "allow",
          supporting: { returned: result.length },
        });
        return result;
      });

      const agents = rows.map((row) => ({
        id: row.id,
        slug: row.slug,
        display_name: row.display_name,
        kind: row.kind,
        owner_user_id: row.owner_user_id,
        status: row.status,
        created_at:
          row.created_at instanceof Date
            ? row.created_at.toISOString()
            : new Date(row.created_at).toISOString(),
      }));
      return c.json({ agents });
    } catch (e) {
      const message = e instanceof Error ? e.message : "list failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });

  app.post("/v1/agents/:agentId/capabilities", async (c) => {
    const agentId = c.req.param("agentId");

    let body: MintBody;
    try {
      body = (await c.req.json()) as MintBody;
    } catch {
      return c.json({ error: "invalid_body", message: "invalid json body" }, 400);
    }
    const parsed = parseMintBody(body);
    if (typeof parsed === "string") {
      return c.json({ error: "invalid_body", message: parsed }, 400);
    }

    if (!isUuid(agentId)) {
      return c.json({ error: "not_found", message: "agent not found" }, 404);
    }

    const probeDb = createClient(c.env.DATABASE_URL);
    const agentLookup = (await probeDb.execute(
      sql`SELECT workspace_id FROM agents WHERE id = ${agentId} LIMIT 1`,
    )) as Array<{ workspace_id: string }>;
    const workspaceId = agentLookup[0]?.workspace_id;
    if (!workspaceId) {
      return c.json({ error: "not_found", message: "agent not found" }, 404);
    }

    const ctx = await adminAuth(c, workspaceId);
    if (ctx instanceof Response) return ctx;

    const limiter = pickLimiter(c.env);
    const bucket = `mcp::agent-mint::${workspaceId}::${agentId}`;
    const rate = await limiter.hit(bucket, RATE_LIMIT_PER_MIN, 60);
    c.header("x-ratelimit-limit", String(RATE_LIMIT_PER_MIN));
    c.header("x-ratelimit-remaining", String(rate.remaining));
    c.header("x-ratelimit-reset", String(Math.ceil(rate.resetAt / 1000)));
    if (!rate.allowed) {
      const retryAfter = Math.max(Math.ceil((rate.resetAt - Date.now()) / 1000), 1);
      c.header("retry-after", String(retryAfter));
      return c.json({ error: "rate_limited" }, 429);
    }

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = decodeMek(c.env);

    try {
      const result = await withWorkspace(db, workspaceId, async (tx) => {
        const agent = await loadAgent(tx, workspaceId, agentId);
        if (!agent) {
          return {
            kind: "error" as const,
            status: 404,
            code: "not_found",
            message: "agent not found",
          };
        }
        if (agent.status !== "active") {
          return {
            kind: "error" as const,
            status: 403,
            code: "agent_inactive",
            message: "agent is not active",
          };
        }

        const subject = await resolveOnBehalfOf(tx, workspaceId, parsed.onBehalfOf);
        if (!subject) {
          return {
            kind: "error" as const,
            status: 404,
            code: "not_found",
            message: "on_behalf_of user not found",
          };
        }

        const audienceRow = await lookupAudience(tx, workspaceId, parsed.audience);
        if (!audienceRow) {
          return {
            kind: "error" as const,
            status: 400,
            code: "unknown_audience",
            message: `Audience "${parsed.audience}" not registered for workspace`,
          };
        }
        if (!subjectAllowedByPatterns(subject.email, audienceRow.allowedSubjectPatterns)) {
          return {
            kind: "error" as const,
            status: 400,
            code: "subject_not_allowed",
            message: `Subject not allowed by audience "${parsed.audience}"`,
          };
        }

        const grant = await findGrant(tx, {
          workspaceId,
          agentId,
          toolName: parsed.toolName,
          audience: parsed.audience,
          userId: subject.id,
          userEmail: subject.email,
          scope: parsed.scope,
        });
        if (!grant) {
          return {
            kind: "error" as const,
            status: 403,
            code: "no_matching_grant",
            message: "no capability grant matches the request",
          };
        }

        if (!ctx.roles.includes("admin") && grant.created_by_user_id !== ctx.userId) {
          return {
            kind: "error" as const,
            status: 403,
            code: "forbidden",
            message: "caller is not the grant owner",
          };
        }

        if (grant.expires_at !== null) {
          const grantExp =
            grant.expires_at instanceof Date ? grant.expires_at : new Date(grant.expires_at);
          if (!Number.isNaN(grantExp.getTime()) && grantExp.getTime() <= Date.now()) {
            await writeAgentAudit(tx, {
              workspaceId,
              rawMek,
              actorUserId: ctx.userId,
              action: "agent.capability.minted",
              target: { agent_id: agentId, grant_id: grant.id, tool_name: parsed.toolName },
              decision: "deny",
              supporting: { reason: "grant_expired", expires_at: grantExp.toISOString() },
            });
            return {
              kind: "error" as const,
              status: 403,
              code: "grant_expired",
              message: "capability grant has expired",
            };
          }
        }

        const recent = await countRecentInvocations(tx, workspaceId, grant.id);
        if (recent >= grant.max_uses_per_day) {
          await writeAgentAudit(tx, {
            workspaceId,
            rawMek,
            actorUserId: ctx.userId,
            action: "agent.capability.minted",
            target: { agent_id: agentId, grant_id: grant.id, tool_name: parsed.toolName },
            decision: "deny",
            supporting: { reason: "quota_exceeded", used: recent, limit: grant.max_uses_per_day },
          });
          return {
            kind: "error" as const,
            status: 409,
            code: "quota_exceeded",
            message: "daily grant quota exceeded",
          };
        }

        const cnfThumbprint = await sdjwt.jwkThumbprint(parsed.cnfJwk as sdjwt.CnfJwk);

        const jti = crypto.randomUUID();
        const iat = Math.floor(Date.now() / 1000);
        const exp = iat + parsed.ttlSeconds;

        // RFC 7800: cnf.jwk is sufficient for the verifier to bind a kb-jwt;
        // the jkt form is only useful for fast lookup which we do not need.
        // issueSdJwt embeds cnf.jwk from opts.cnfJkt, so do not duplicate here.
        const issuerClaims: Record<string, unknown> = {
          iss: c.env.ISSUER_BASE_URL,
          sub: `agent_${agentId}`,
          aud: parsed.audience,
          iat,
          exp,
          jti,
          org: workspaceId,
          mode: "agent",
          parent_jti: null,
          on_behalf_of: subject.email,
          tool_name: parsed.toolName,
          max_redeems: parsed.maxRedeems,
        };
        if (parsed.intentJti) issuerClaims.intent_jti = parsed.intentJti;

        const disclosures: sdjwt.SdJwtDisclosureInput[] = [
          { name: "policy", value: { scope: parsed.scope } },
          {
            name: "payload",
            value: { user_id: subject.id, user_email: subject.email, agent_id: agentId },
          },
          { name: "audience", value: parsed.audience },
        ];

        const key = await loadActiveSigningKey(tx, workspaceId, "jwt", rawMek);
        const compactSdJwt = await sdjwt.issueSdJwt({
          issuerPrivateKey: key.privateKey,
          issuerKid: key.id,
          issuerClaims,
          disclosures,
          cnfJkt: parsed.cnfJwk as sdjwt.CnfJwk,
        });

        await tx.execute(
          sql`INSERT INTO agent_invocations (
            workspace_id, jti, parent_jti, agent_id, agent_id_snapshot, grant_id,
            on_behalf_of_user_id, on_behalf_of_user_id_snapshot,
            tool_name, scope_claim, audience, intent_jti, cnf_thumbprint,
            redeem_status, redeem_count, max_redeems, issued_at, expires_at
          ) VALUES (
            ${workspaceId}, ${jti}::uuid, NULL, ${agentId}::uuid, ${agentId}::uuid, ${grant.id}::uuid,
            ${subject.id}::uuid, ${subject.id}::uuid,
            ${parsed.toolName}, ${JSON.stringify(parsed.scope)}::jsonb, ${parsed.audience},
            ${parsed.intentJti}, ${cnfThumbprint}, 'issued', 0, ${parsed.maxRedeems},
            to_timestamp(${iat}), to_timestamp(${exp})
          )`,
        );

        await writeAgentAudit(tx, {
          workspaceId,
          rawMek,
          actorUserId: ctx.userId,
          action: "agent.capability.minted",
          target: {
            agent_id: agentId,
            grant_id: grant.id,
            jti,
            audience: parsed.audience,
            tool_name: parsed.toolName,
          },
          decision: "allow",
        });

        return {
          kind: "ok" as const,
          payload: {
            jti,
            sd_jwt: compactSdJwt,
            exp,
            cnf_thumbprint: cnfThumbprint,
          },
        };
      });

      if (result.kind === "error") {
        return c.json(
          { error: result.code, message: result.message },
          result.status as 400 | 403 | 404 | 409,
        );
      }
      return c.json(result.payload, 201);
    } catch (e) {
      const message = e instanceof Error ? e.message : "mint failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });

  app.delete("/v1/capabilities/:jti", async (c) => {
    const jti = c.req.param("jti");
    if (!isUuid(jti)) {
      return c.json({ error: "not_found", message: "capability not found" }, 404);
    }

    let body: RevokeBody = {};
    const raw = await c.req.text();
    if (raw.length > 0) {
      try {
        body = JSON.parse(raw) as RevokeBody;
      } catch {
        return c.json({ error: "invalid_body", message: "invalid json body" }, 400);
      }
      if (!isRecordObject(body)) {
        return c.json({ error: "invalid_body", message: "body must be an object" }, 400);
      }
    }

    const cascade = body.cascade === undefined ? true : Boolean(body.cascade);
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

    const workspaceId = await findWorkspaceIdForJti(c.env.DATABASE_URL, jti);
    if (!workspaceId) {
      return c.json({ error: "not_found", message: "capability not found" }, 404);
    }

    const ctx = await adminAuth(c, workspaceId);
    if (ctx instanceof Response) return ctx;

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = decodeMek(c.env);

    try {
      const revoked = await withWorkspace(db, workspaceId, async (tx) => {
        const found = (await tx.execute(
          sql`SELECT jti FROM agent_invocations
              WHERE workspace_id = ${workspaceId} AND jti = ${jti}::uuid
              FOR UPDATE`,
        )) as Array<{ jti: string }>;
        if (found.length === 0) return null;

        const all = new Set<string>([jti]);
        if (cascade) {
          let frontier: string[] = [jti];
          while (frontier.length > 0 && all.size < CASCADE_MAX) {
            const params = sql.join(
              frontier.map((id) => sql`${id}::uuid`),
              sql`, `,
            );
            const children = (await tx.execute(
              sql`SELECT child_jti FROM delegation_chains
                  WHERE workspace_id = ${workspaceId}
                    AND parent_jti IN (${params})`,
            )) as Array<{ child_jti: string }>;
            const next: string[] = [];
            for (const row of children) {
              const id = row.child_jti;
              if (!all.has(id)) {
                all.add(id);
                next.push(id);
              }
            }
            frontier = next;
          }
        }

        const list = [...all];
        const listParams = sql.join(
          list.map((id) => sql`${id}::uuid`),
          sql`, `,
        );
        await tx.execute(
          sql`UPDATE agent_invocations
              SET redeem_status = 'revoked', deny_reason = COALESCE(${reason}, deny_reason)
              WHERE workspace_id = ${workspaceId} AND jti IN (${listParams})`,
        );

        for (const id of list) {
          await tx
            .insert(revokedJtis)
            .values({
              workspaceId,
              jti: id,
              revokedBy: ctx.userId,
              reason: reason ?? "agent_capability_revoked",
            })
            .onConflictDoNothing({ target: [revokedJtis.workspaceId, revokedJtis.jti] });

          await writeAgentAudit(tx, {
            workspaceId,
            rawMek,
            actorUserId: ctx.userId,
            action: "agent.capability.revoked",
            target: { jti: id, cascade, root_jti: jti },
            decision: "allow",
            supporting: { revocation_reason: reason },
          });
        }

        return list;
      });

      if (!revoked) {
        return c.json({ error: "not_found", message: "capability not found" }, 404);
      }
      return c.json({ revoked, count: revoked.length });
    } catch (e) {
      const message = e instanceof Error ? e.message : "revoke failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });
};
