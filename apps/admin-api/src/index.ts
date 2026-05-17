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
  driveDocumentChunks,
  groupMembers,
  groups,
  invites,
  policies,
  revokedJtis,
  users,
  workspaceOauthConnections,
} from "@getpact/db/schema";
import {
  type AnalyticsEngineDataset,
  createLogger,
  type MetricsClient,
  metricsFromEnv,
  requestLogger,
  type SentryClient,
  sentryFromEnv,
} from "@getpact/logger";
import { tryParsePolicy } from "@getpact/policy";
import { deleteSecret, loadSecretString, storeSecret } from "@getpact/vault";
import { and, desc, eq, max, sql } from "drizzle-orm";
import type { Context } from "hono";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { writeAdminAudit } from "./audit.js";
import { type AdminContext, authenticateAdmin } from "./auth.js";
import { bustRevocationCache, type KVNamespace } from "./cache.js";
import { registerAuditRoutes } from "./routes/audit.js";
import { registerSendCapRoutes } from "./routes/send-caps.js";

export type Env = {
  DATABASE_URL: string;
  MEK: string;
  ISSUER_BASE_URL: string;
  ENVIRONMENT?: string;
  ADMIN_AUDIENCE?: string;
  AUDIT_AUDIENCE?: string;
  UPSTREAM_HOST_ALLOWLIST?: string;
  GOOGLE_OAUTH_CLIENT_ID?: string;
  GOOGLE_OAUTH_CLIENT_SECRET?: string;
  GOOGLE_OAUTH_TOKEN_ENDPOINT?: string;
  GOOGLE_OAUTH_JWKS_URI?: string;
  GOOGLE_OAUTH_ISSUER?: string;
  GOOGLE_OAUTH_REVOKE_ENDPOINT?: string;
  GOOGLE_DRIVE_OAUTH_REDIRECT_URI?: string;
  REVOCATION_CACHE?: KVNamespace;
  SENTRY_DSN?: string;
  SENTRY_ENVIRONMENT?: string;
  SENTRY_RELEASE?: string;
  METRICS?: AnalyticsEngineDataset;
  PACT_REPLAY_RETENTION_DAYS?: string;
};
type AppVariables = {
  sentry: SentryClient;
  metrics: MetricsClient;
};

type AppCtx = Context<{ Bindings: Env; Variables: AppVariables }>;

const app = new Hono<{ Bindings: Env; Variables: AppVariables }>();

const logger = createLogger({ base: { app: "admin-api" } });
app.use("*", requestLogger(logger, "admin-api"));
app.use("*", async (c, next) => {
  const sentry = sentryFromEnv(c.env, "admin-api");
  const metrics = metricsFromEnv(c.env, "admin-api");
  c.set("sentry", sentry);
  c.set("metrics", metrics);
  try {
    await next();
  } catch (err) {
    sentry.captureRequest(c.req.raw, err);
    throw err;
  }
});
app.use("*", async (c, next) => {
  await next();
  const headers = securityHeaders({ production: c.env.ENVIRONMENT === "production" });
  for (const [k, v] of Object.entries(headers)) c.header(k, v);
});
app.use("/v1/*", bodyLimit({ maxSize: 64 * 1024 }));

app.get("/health", (c) => c.json({ ok: true }));

registerAuditRoutes(app);
registerSendCapRoutes(app);

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

const DRIVE_PROVIDER = "google_drive";
const DRIVE_SECRET_KIND = "google_drive_oauth";
const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.readonly";
const GOOGLE_USERINFO_EMAIL_SCOPE = "https://www.googleapis.com/auth/userinfo.email";
const GOOGLE_USERINFO_PROFILE_SCOPE = "https://www.googleapis.com/auth/userinfo.profile";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const GOOGLE_REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke";
const GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUER = "https://accounts.google.com";

type DriveTokenPayload = {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: string;
  scope?: string;
  googleSub: string;
  email: string;
};

type DriveExchangeResult = DriveTokenPayload & {
  scopes: string[];
};

class DriveConnectionRejectedError extends ValidationError {
  constructor(
    message: string,
    readonly auditTarget: { reason: string; email: string },
  ) {
    super(message);
  }
}

const driveVaultTarget = (userId: string): string => `user:${userId}`;

const connectionStatus = (expiresAt: Date | null, status: string): string => {
  if (status !== "connected") return status;
  if (expiresAt && expiresAt.getTime() <= Date.now()) return "expired";
  return "connected";
};

const parseScopes = (scope: string | undefined): string[] =>
  scope
    ? scope
        .split(/\s+/)
        .map((value) => value.trim())
        .filter(Boolean)
    : [];

const allowedDriveScopes = new Set([
  "openid",
  "email",
  "profile",
  GOOGLE_USERINFO_EMAIL_SCOPE,
  GOOGLE_USERINFO_PROFILE_SCOPE,
  DRIVE_SCOPE,
]);

export const validateDriveScopes = (scope: string | undefined): string[] => {
  const scopes = parseScopes(scope);
  if (!scopes.includes(DRIVE_SCOPE)) {
    throw new ValidationError("google drive readonly scope was not granted");
  }
  if (scopes.some((granted) => !allowedDriveScopes.has(granted))) {
    throw new ValidationError("google drive granted unexpected scopes");
  }
  return scopes;
};

const isDriveTokenPayload = (value: unknown): value is DriveTokenPayload => {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.accessToken === "string" &&
    typeof record.googleSub === "string" &&
    typeof record.email === "string"
  );
};

const requireDriveOAuthConfig = (
  c: AppCtx,
): {
  clientId: string;
  clientSecret: string;
  tokenEndpoint: string;
  jwksUri: string;
  issuer: string;
} => {
  if (!c.env.GOOGLE_OAUTH_CLIENT_ID || !c.env.GOOGLE_OAUTH_CLIENT_SECRET) {
    throw new ValidationError("google drive oauth is not configured");
  }
  return {
    clientId: c.env.GOOGLE_OAUTH_CLIENT_ID,
    clientSecret: c.env.GOOGLE_OAUTH_CLIENT_SECRET,
    tokenEndpoint: c.env.GOOGLE_OAUTH_TOKEN_ENDPOINT ?? GOOGLE_TOKEN_ENDPOINT,
    jwksUri: c.env.GOOGLE_OAUTH_JWKS_URI ?? GOOGLE_JWKS_URI,
    issuer: c.env.GOOGLE_OAUTH_ISSUER ?? GOOGLE_ISSUER,
  };
};

const exchangeDriveCode = async (
  c: AppCtx,
  input: { code: string; codeVerifier: string; redirectUri: string; nonce: string },
): Promise<DriveExchangeResult> => {
  const config = requireDriveOAuthConfig(c);
  const expectedRedirect = c.env.GOOGLE_DRIVE_OAUTH_REDIRECT_URI;
  if (c.env.ENVIRONMENT === "production" && !expectedRedirect) {
    throw new ValidationError("google drive redirect uri is not configured");
  }
  if (expectedRedirect && input.redirectUri !== expectedRedirect) {
    throw new ValidationError("redirectUri does not match configured Drive callback");
  }

  const tokenRes = await fetch(config.tokenEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    signal: AbortSignal.timeout(10_000),
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code: input.code,
      code_verifier: input.codeVerifier,
      grant_type: "authorization_code",
      redirect_uri: input.redirectUri,
    }),
  });

  const rawBody = await tokenRes.text();
  if (!tokenRes.ok) {
    throw new ValidationError("google drive token exchange failed");
  }
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(rawBody) as Record<string, unknown>;
  } catch {
    throw new ValidationError("google drive token response was not json");
  }
  if (typeof body.access_token !== "string" || typeof body.id_token !== "string") {
    throw new ValidationError("google drive token response missing tokens");
  }

  let payload: Awaited<ReturnType<typeof jwtVerify>>["payload"];
  try {
    ({ payload } = await jwtVerify(body.id_token, createRemoteJWKSet(new URL(config.jwksUri)), {
      issuer: config.issuer,
      audience: config.clientId,
      algorithms: ["RS256"],
    }));
  } catch {
    throw new ValidationError("google drive identity verification failed");
  }
  if (payload.nonce !== input.nonce) {
    throw new ValidationError("google drive identity nonce mismatch");
  }
  if (typeof payload.sub !== "string" || typeof payload.email !== "string") {
    throw new ValidationError("google drive identity missing sub or email");
  }

  const expiresAt =
    typeof body.expires_in === "number"
      ? new Date(Date.now() + body.expires_in * 1000).toISOString()
      : undefined;
  const scope = typeof body.scope === "string" ? body.scope : undefined;
  const scopes = validateDriveScopes(scope);

  const result: DriveExchangeResult = {
    accessToken: body.access_token,
    googleSub: payload.sub,
    email: canonicalizeEmail(payload.email) as string,
    scopes,
  };
  if (typeof body.refresh_token === "string") result.refreshToken = body.refresh_token;
  if (expiresAt) result.expiresAt = expiresAt;
  if (scope) result.scope = scope;
  return result;
};

type GoogleRevokeResult =
  | { ok: true; alreadyInvalid: false }
  | { ok: false; alreadyInvalid: boolean; error: string };

const revokeGoogleToken = async (env: Env, token: string): Promise<GoogleRevokeResult> => {
  const response = await fetch(env.GOOGLE_OAUTH_REVOKE_ENDPOINT ?? GOOGLE_REVOKE_ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    signal: AbortSignal.timeout(10_000),
    body: new URLSearchParams({ token }),
  });
  if (response.ok) return { ok: true, alreadyInvalid: false };
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  const error = typeof body.error === "string" ? body.error : `http_${response.status}`;
  return { ok: false, alreadyInvalid: error === "invalid_token", error };
};

app.get("/v1/workspaces/:id/connections/google-drive", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const db = createClient(c.env.DATABASE_URL);
  const [row] = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .select({
        id: workspaceOauthConnections.id,
        email: workspaceOauthConnections.email,
        scopes: workspaceOauthConnections.scopes,
        status: workspaceOauthConnections.status,
        expiresAt: workspaceOauthConnections.expiresAt,
        connectedAt: workspaceOauthConnections.connectedAt,
        lastRefreshAt: workspaceOauthConnections.lastRefreshAt,
        lastError: workspaceOauthConnections.lastError,
      })
      .from(workspaceOauthConnections)
      .where(
        and(
          eq(workspaceOauthConnections.workspaceId, workspaceId),
          eq(workspaceOauthConnections.provider, DRIVE_PROVIDER),
          eq(workspaceOauthConnections.userId, ctx.userId),
          sql`${workspaceOauthConnections.disconnectedAt} IS NULL`,
        ),
      )
      .limit(1),
  );

  if (!row) {
    return c.json({ connection: { status: "not_configured" } });
  }

  return c.json({
    connection: {
      id: row.id,
      status: connectionStatus(row.expiresAt, row.status),
      email: row.email,
      scopes: row.scopes,
      expiresAt: row.expiresAt?.toISOString(),
      connectedAt: row.connectedAt.toISOString(),
      lastRefreshAt: row.lastRefreshAt?.toISOString(),
      lastError: row.lastError,
    },
  });
});

app.post("/v1/workspaces/:id/connections/google-drive/oauth", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  try {
    const body = await c.req.json<{
      code?: string;
      codeVerifier?: string;
      nonce?: string;
      redirectUri?: string;
    }>();
    if (!body.code || !body.codeVerifier || !body.nonce || !body.redirectUri) {
      throw new ValidationError("code, codeVerifier, nonce, and redirectUri are required");
    }

    const exchanged = await exchangeDriveCode(c, {
      code: body.code,
      codeVerifier: body.codeVerifier,
      nonce: body.nonce,
      redirectUri: body.redirectUri,
    });
    const db = createClient(c.env.DATABASE_URL);
    const rawMek = fromBase64(c.env.MEK);
    const vaultTarget = driveVaultTarget(ctx.userId);

    const connection = await withWorkspace(db, workspaceId, async (tx) => {
      const lockedUsers = (await tx.execute(sql`
        SELECT id, email, google_sub AS "googleSub"
        FROM users
        WHERE workspace_id = ${workspaceId}
          AND id = ${ctx.userId}
        FOR UPDATE
      `)) as Array<{ id: string; email: string; googleSub: string | null }>;
      const user = lockedUsers[0];
      if (!user) throw new ValidationError("user not found");
      if (!user.googleSub || user.googleSub !== exchanged.googleSub) {
        throw new DriveConnectionRejectedError(
          "google drive identity does not match signed-in user",
          { reason: "google_sub_mismatch", email: exchanged.email },
        );
      }

      const existingSecret = await loadSecretString(tx, rawMek, {
        workspaceId,
        kind: DRIVE_SECRET_KIND,
        target: vaultTarget,
      });
      let existingRefreshToken: string | undefined;
      if (existingSecret) {
        try {
          const parsed = JSON.parse(existingSecret) as unknown;
          if (isDriveTokenPayload(parsed)) {
            existingRefreshToken = parsed.refreshToken;
          }
        } catch {}
      }

      const tokenPayload: DriveTokenPayload = {
        accessToken: exchanged.accessToken,
        googleSub: exchanged.googleSub,
        email: exchanged.email,
      };
      const refreshToken = exchanged.refreshToken ?? existingRefreshToken;
      if (!refreshToken) {
        throw new DriveConnectionRejectedError(
          "google drive did not return an offline refresh token; reconnect and approve offline access",
          { reason: "missing_refresh_token", email: exchanged.email },
        );
      }
      tokenPayload.refreshToken = refreshToken;
      if (exchanged.expiresAt) tokenPayload.expiresAt = exchanged.expiresAt;
      if (exchanged.scope) tokenPayload.scope = exchanged.scope;
      await storeSecret(tx, rawMek, {
        workspaceId,
        kind: DRIVE_SECRET_KIND,
        target: vaultTarget,
        plaintext: JSON.stringify(tokenPayload),
      });

      const [active] = await tx
        .select({ id: workspaceOauthConnections.id })
        .from(workspaceOauthConnections)
        .where(
          and(
            eq(workspaceOauthConnections.workspaceId, workspaceId),
            eq(workspaceOauthConnections.provider, DRIVE_PROVIDER),
            eq(workspaceOauthConnections.userId, ctx.userId),
            sql`${workspaceOauthConnections.disconnectedAt} IS NULL`,
          ),
        )
        .limit(1);

      const values = {
        workspaceId,
        provider: DRIVE_PROVIDER,
        userId: ctx.userId,
        providerSubject: exchanged.googleSub,
        email: exchanged.email,
        scopes: exchanged.scopes,
        status: "connected",
        vaultTarget,
        expiresAt: exchanged.expiresAt ? new Date(exchanged.expiresAt) : null,
        lastError: null,
      };
      const rows = active
        ? await tx
            .update(workspaceOauthConnections)
            .set({
              providerSubject: values.providerSubject,
              email: values.email,
              scopes: values.scopes,
              status: values.status,
              vaultTarget: values.vaultTarget,
              expiresAt: values.expiresAt,
              connectedAt: new Date(),
              lastError: null,
            })
            .where(eq(workspaceOauthConnections.id, active.id))
            .returning({
              id: workspaceOauthConnections.id,
              email: workspaceOauthConnections.email,
              expiresAt: workspaceOauthConnections.expiresAt,
            })
        : await tx.insert(workspaceOauthConnections).values(values).returning({
            id: workspaceOauthConnections.id,
            email: workspaceOauthConnections.email,
            expiresAt: workspaceOauthConnections.expiresAt,
          });
      await auditInTx(tx, c, ctx, "admin.connection.google_drive.connected", {
        connectionId: rows[0]?.id,
        email: exchanged.email,
        scopes: exchanged.scopes,
      });
      return rows[0];
    });

    return c.json({
      connection: {
        id: connection?.id,
        status: "connected",
        email: connection?.email,
        expiresAt: connection?.expiresAt?.toISOString(),
      },
    });
  } catch (e) {
    if (e instanceof DriveConnectionRejectedError) {
      try {
        await withWorkspace(createClient(c.env.DATABASE_URL), workspaceId, (tx) =>
          auditInTx(tx, c, ctx, "admin.connection.google_drive.rejected", e.auditTarget, "deny"),
        );
      } catch {
        return c.json({ error: "audit_unavailable" }, 503);
      }
      return c.json({ error: e.code, message: e.message }, e.status as 400);
    }
    if (isUniqueViolation(e)) {
      return c.json(
        { error: "conflict", message: "active Google Drive connection already exists" },
        409,
      );
    }
    if (e instanceof PactError) {
      return c.json({ error: e.code, message: e.message }, e.status as 400 | 401 | 403 | 404);
    }
    throw e;
  }
});

app.delete("/v1/workspaces/:id/connections/google-drive", async (c) => {
  const workspaceId = c.req.param("id");
  const ctx = await auth(c, workspaceId);
  if (!isContext(ctx)) return ctx;

  const db = createClient(c.env.DATABASE_URL);
  const rawMek = fromBase64(c.env.MEK);
  const vaultTarget = driveVaultTarget(ctx.userId);
  const existingSecret = await withWorkspace(db, workspaceId, (tx) =>
    loadSecretString(tx, rawMek, {
      workspaceId,
      kind: DRIVE_SECRET_KIND,
      target: vaultTarget,
    }),
  );
  if (existingSecret) {
    let revokeToken: string | undefined;
    try {
      const parsed = JSON.parse(existingSecret) as unknown;
      if (isDriveTokenPayload(parsed)) {
        revokeToken = parsed.refreshToken ?? parsed.accessToken;
      }
    } catch {}
    if (revokeToken) {
      try {
        await withWorkspace(db, workspaceId, (tx) =>
          auditInTx(tx, c, ctx, "admin.connection.google_drive.disconnect_attempt", {
            hasGoogleToken: true,
          }),
        );
      } catch {
        return c.json({ error: "audit_unavailable" }, 503);
      }
      const revoked = await revokeGoogleToken(c.env, revokeToken).catch((error) => ({
        ok: false as const,
        alreadyInvalid: false,
        error: error instanceof Error ? error.message : "google_revoke_failed",
      }));
      if (!revoked.ok && !revoked.alreadyInvalid) {
        try {
          await withWorkspace(db, workspaceId, (tx) =>
            auditInTx(
              tx,
              c,
              ctx,
              "admin.connection.google_drive.disconnect_rejected",
              { reason: "google_revoke_failed", error: revoked.error },
              "deny",
            ),
          );
        } catch {
          return c.json({ error: "audit_unavailable" }, 503);
        }
        return c.json(
          { error: "google_revoke_failed", message: "Google Drive grant could not be revoked" },
          502,
        );
      }
    }
  }
  const removed = await withWorkspace(db, workspaceId, async (tx) => {
    const rows = await tx
      .update(workspaceOauthConnections)
      .set({ status: "disconnected", disconnectedAt: new Date() })
      .where(
        and(
          eq(workspaceOauthConnections.workspaceId, workspaceId),
          eq(workspaceOauthConnections.provider, DRIVE_PROVIDER),
          eq(workspaceOauthConnections.userId, ctx.userId),
          sql`${workspaceOauthConnections.disconnectedAt} IS NULL`,
        ),
      )
      .returning({
        id: workspaceOauthConnections.id,
        vaultTarget: workspaceOauthConnections.vaultTarget,
      });
    if (rows[0]) {
      await deleteSecret(tx, {
        workspaceId,
        kind: DRIVE_SECRET_KIND,
        target: rows[0].vaultTarget,
      });
    }
    const purgedChunks = await tx
      .delete(driveDocumentChunks)
      .where(
        and(
          eq(driveDocumentChunks.workspaceId, workspaceId),
          eq(driveDocumentChunks.userId, ctx.userId),
        ),
      )
      .returning({ id: driveDocumentChunks.id });
    if (rows[0] || purgedChunks.length > 0) {
      await auditInTx(tx, c, ctx, "admin.connection.google_drive.disconnected", {
        connectionId: rows[0]?.id,
        purgedDriveChunks: purgedChunks.length,
      });
    }
    return { rows, purgedChunks };
  });
  if (removed.rows.length === 0 && removed.purgedChunks.length === 0) {
    return c.json({ connection: { status: "not_configured" } });
  }
  return c.json({ ok: true, purgedDriveChunks: removed.purgedChunks.length });
});

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

const DEFAULT_REPLAY_RETENTION_DAYS = 7;
const MAX_REPLAY_RETENTION_DAYS = 3650;

const replayRetentionDays = (env: Env): number => {
  const raw = env.PACT_REPLAY_RETENTION_DAYS;
  if (!raw) return DEFAULT_REPLAY_RETENTION_DAYS;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > MAX_REPLAY_RETENTION_DAYS) {
    return DEFAULT_REPLAY_RETENTION_DAYS;
  }
  return parsed;
};

export const pruneReplayLog = async (env: Env): Promise<{ deleted: number; days: number }> => {
  const days = replayRetentionDays(env);
  const interval = `${days} days`;
  const db = createClient(env.DATABASE_URL, { max: 1, idle_timeout: 1 });
  try {
    const rows = (await db.execute(
      sql`SELECT prune_kbjwt_replay_log(${interval}::interval) AS deleted`,
    )) as Array<{ deleted: number | string | bigint }>;
    const raw = rows[0]?.deleted ?? 0;
    const deleted = typeof raw === "number" ? raw : Number(raw);
    return { deleted, days };
  } finally {
    await db.$client.end({ timeout: 5 });
  }
};

export default app;
