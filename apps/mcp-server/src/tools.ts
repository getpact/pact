import { createDriveAdapter, type DriveConnection } from "@getpact/adapter-drive";
import {
  type Adapter,
  type AdapterContext,
  type AdapterTool,
  buildToolRegistry,
  json,
  type ToolDeps,
  type ToolDescriptor,
} from "@getpact/adapter-sdk";
import { createSlackAdapter } from "@getpact/adapter-slack";
import { createClient, type Tx, withWorkspace } from "@getpact/db";
import { auditEvents, policies, workspaceOauthConnections, workspaces } from "@getpact/db/schema";
import { loadSecretString, storeSecret } from "@getpact/vault";
import { and, desc, eq, isNull, sql } from "drizzle-orm";

export type { ToolDeps, ToolDescriptor, ToolResult } from "@getpact/adapter-sdk";
export type Tool = AdapterTool;

const whoami: AdapterTool = {
  descriptor: {
    name: "pact.whoami",
    description: "Return the verified identity, groups, and roles for the current Pact JWT.",
    inputSchema: { type: "object" },
  },
  authorize: (_args, ctx) => ({
    action: "tool:pact.whoami",
    resource: `workspace:${ctx.workspaceId}:identity`,
  }),
  handler: async (_args, ctx) =>
    json({
      workspaceId: ctx.workspaceId,
      userId: ctx.userId,
      email: ctx.email,
      groups: ctx.groups,
      roles: ctx.roles,
    }),
};

const workspaceInfo: AdapterTool = {
  descriptor: {
    name: "pact.workspace.info",
    description: "Return the workspace metadata visible to the current token.",
    inputSchema: { type: "object" },
  },
  authorize: (_args, ctx) => ({
    action: "tool:pact.workspace.info",
    resource: `workspace:${ctx.workspaceId}:info`,
  }),
  handler: async (_args, ctx, deps) => {
    const db = createClient(deps.databaseUrl);
    const [ws] = await db
      .select({
        id: workspaces.id,
        slug: workspaces.slug,
        name: workspaces.name,
        region: workspaces.region,
        createdAt: workspaces.createdAt,
      })
      .from(workspaces)
      .where(eq(workspaces.id, ctx.workspaceId))
      .limit(1);
    if (!ws) {
      return { content: [{ type: "text", text: "workspace not found" }], isError: true };
    }
    return json({
      id: ws.id,
      slug: ws.slug,
      name: ws.name,
      region: ws.region,
      createdAt: ws.createdAt.toISOString(),
    });
  },
};

const auditRecent: AdapterTool = {
  descriptor: {
    name: "pact.audit.recent",
    description: "Return up to 50 most recent audit events for the current workspace.",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "number" },
        action: { type: "string" },
      },
    },
  },
  authorize: (_args, ctx) => ({
    action: "tool:pact.audit.recent",
    resource: `workspace:${ctx.workspaceId}:audit`,
  }),
  handler: async (args, ctx, deps) => {
    if (!ctx.roles.includes("admin") && !ctx.roles.includes("auditor")) {
      return { content: [{ type: "text", text: "admin or auditor role required" }], isError: true };
    }
    const db = createClient(deps.databaseUrl);
    const limitRaw = typeof args.limit === "number" ? args.limit : 20;
    const limit = Math.max(1, Math.min(50, Math.floor(limitRaw)));
    const action = typeof args.action === "string" ? args.action : undefined;

    const conditions = [eq(auditEvents.workspaceId, ctx.workspaceId)];
    if (action) conditions.push(eq(auditEvents.action, action));

    const rows = await withWorkspace(db, ctx.workspaceId, (tx) =>
      tx
        .select({
          ts: auditEvents.ts,
          actorKind: auditEvents.actorKind,
          actorId: auditEvents.actorId,
          action: auditEvents.action,
          decision: auditEvents.decision,
        })
        .from(auditEvents)
        .where(and(...conditions))
        .orderBy(desc(auditEvents.ts))
        .limit(limit),
    );
    return json({
      events: rows.map((r) => ({
        ts: r.ts.toISOString(),
        actorKind: r.actorKind,
        actorId: r.actorId,
        action: r.action,
        decision: r.decision,
      })),
    });
  },
};

const policyActive: AdapterTool = {
  descriptor: {
    name: "pact.policy.active",
    description: "Return the active policy version body for the current workspace.",
    inputSchema: { type: "object" },
  },
  authorize: (_args, ctx) => ({
    action: "tool:pact.policy.active",
    resource: `workspace:${ctx.workspaceId}:policy`,
  }),
  handler: async (_args, ctx, deps) => {
    if (!ctx.roles.includes("admin")) {
      return { content: [{ type: "text", text: "admin role required" }], isError: true };
    }
    const db = createClient(deps.databaseUrl);
    const [row] = await withWorkspace(db, ctx.workspaceId, (tx) =>
      tx
        .select({
          version: policies.version,
          body: policies.body,
          createdAt: policies.createdAt,
        })
        .from(policies)
        .where(and(eq(policies.workspaceId, ctx.workspaceId), isNull(policies.replacedAt)))
        .orderBy(desc(policies.version))
        .limit(1),
    );
    if (!row) {
      return { content: [{ type: "text", text: "no active policy" }] };
    }
    return json({
      version: row.version,
      createdAt: row.createdAt.toISOString(),
      body: row.body,
    });
  },
};

const pactAdapter: Adapter = {
  name: "pact",
  tools: [whoami, workspaceInfo, auditRecent, policyActive],
};

const slackAdapter = createSlackAdapter({
  loadBotToken: async (ctx, deps) => {
    if (!deps.rawMek) return null;
    const db = createClient(deps.databaseUrl);
    return withWorkspace(db, ctx.workspaceId, (tx) =>
      loadSecretString(tx, deps.rawMek as Uint8Array, {
        workspaceId: ctx.workspaceId,
        kind: "slack",
        target: "bot-token",
      }),
    );
  },
});

const DRIVE_PROVIDER = "google_drive";
const DRIVE_SECRET_KIND = "google_drive_oauth";
const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.readonly";
const DRIVE_REFRESH_SKEW_MS = 60_000;
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const allowedDriveScopes = new Set([
  "openid",
  "email",
  "profile",
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
  DRIVE_SCOPE,
]);

const driveAdapter = createDriveAdapter({
  loadConnection: loadDriveConnection,
});

const defaultAdapters: Adapter[] = [pactAdapter, slackAdapter, driveAdapter];

function parseDriveConnection(value: string | null): DriveConnection | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<DriveConnection>;
    if (typeof parsed.accessToken !== "string" || parsed.accessToken.length === 0) {
      return null;
    }
    const connection: DriveConnection = {
      accessToken: parsed.accessToken,
    };
    if (typeof parsed.refreshToken === "string") connection.refreshToken = parsed.refreshToken;
    if (typeof parsed.expiresAt === "string") connection.expiresAt = parsed.expiresAt;
    if (typeof parsed.scope === "string") connection.scope = parsed.scope;
    if (typeof parsed.googleSub === "string") connection.googleSub = parsed.googleSub;
    if (typeof parsed.email === "string") connection.email = parsed.email;
    return connection;
  } catch {
    return null;
  }
}

type DriveConnectionRow = {
  id: string;
  vaultTarget: string;
  status: string;
  expiresAt: Date | string | null;
};

type LoadedDriveConnection = {
  row: DriveConnectionRow;
  connection: DriveConnection;
};

async function loadDriveConnection(
  ctx: AdapterContext,
  deps: ToolDeps,
): Promise<DriveConnection | null> {
  if (!deps.rawMek) throw new Error("Drive credential store is not configured");
  const db = createClient(deps.databaseUrl);
  const snapshot = await withWorkspace(db, ctx.workspaceId, (tx) =>
    loadDriveConnectionSnapshot(tx, ctx, deps, false),
  );
  if (!snapshot) return null;
  if (!shouldRefreshDriveConnection(snapshot.row, snapshot.connection)) {
    return snapshot.connection;
  }
  if (!snapshot.connection.refreshToken) {
    await withWorkspace(db, ctx.workspaceId, (tx) =>
      markDriveRefreshFailure(tx, snapshot.row.id, "drive refresh token is missing", {
        permanent: true,
      }),
    );
    return null;
  }

  const locked = await withWorkspace(db, ctx.workspaceId, async (tx) => {
    const locked = await loadDriveConnectionSnapshot(tx, ctx, deps, true);
    if (!locked) return null;
    if (!shouldRefreshDriveConnection(locked.row, locked.connection)) {
      return locked;
    }
    if (!locked.connection.refreshToken) {
      await markDriveRefreshFailure(tx, locked.row.id, "drive refresh token is missing", {
        permanent: true,
      });
      return null;
    }
    return locked;
  });
  if (!locked) return null;
  if (!shouldRefreshDriveConnection(locked.row, locked.connection)) {
    return locked.connection;
  }

  const refreshed = await refreshDriveConnection(locked.connection, deps).catch(async (error) => {
    const latest = await withWorkspace(db, ctx.workspaceId, async (tx) => {
      const latest = await loadDriveConnectionSnapshot(tx, ctx, deps, true);
      if (!latest) return null;
      if (!sameDriveRefreshAttempt(locked.connection, latest.connection)) {
        return latest;
      }
      if (!shouldRefreshDriveConnection(latest.row, latest.connection)) {
        return latest;
      }
      await markDriveRefreshFailure(tx, latest.row.id, refreshErrorMessage(error), {
        permanent: isPermanentDriveRefreshError(error),
      });
      return null;
    });
    if (latest && !shouldRefreshDriveConnection(latest.row, latest.connection)) {
      return latest.connection;
    }
    return null;
  });
  if (!refreshed) return null;

  return withWorkspace(db, ctx.workspaceId, async (tx) => {
    const latest = await loadDriveConnectionSnapshot(tx, ctx, deps, true);
    if (!latest) return null;
    if (!shouldRefreshDriveConnection(latest.row, latest.connection)) {
      return latest.connection;
    }
    await storeSecret(tx, deps.rawMek as Uint8Array, {
      workspaceId: ctx.workspaceId,
      kind: DRIVE_SECRET_KIND,
      target: latest.row.vaultTarget,
      plaintext: JSON.stringify(refreshed),
    });
    await tx
      .update(workspaceOauthConnections)
      .set({
        status: "connected",
        expiresAt: refreshed.expiresAt ? new Date(refreshed.expiresAt) : null,
        lastRefreshAt: new Date(),
        lastError: null,
      })
      .where(eq(workspaceOauthConnections.id, latest.row.id));
    return refreshed;
  });
}

async function loadDriveConnectionSnapshot(
  tx: Tx,
  ctx: AdapterContext,
  deps: ToolDeps,
  forUpdate: boolean,
): Promise<LoadedDriveConnection | null> {
  const lockClause = forUpdate ? sql`FOR UPDATE` : sql``;
  const rows = (await tx.execute(sql`
      SELECT id, vault_target AS "vaultTarget", status, expires_at AS "expiresAt"
      FROM workspace_oauth_connections
      WHERE workspace_id = ${ctx.workspaceId}
        AND provider = ${DRIVE_PROVIDER}
        AND user_id = ${ctx.userId}
        AND disconnected_at IS NULL
      LIMIT 1
      ${lockClause}
    `)) as DriveConnectionRow[];
  const row = rows[0];
  if (!row || row.status !== "connected") return null;

  const value = await loadSecretString(tx, deps.rawMek as Uint8Array, {
    workspaceId: ctx.workspaceId,
    kind: DRIVE_SECRET_KIND,
    target: row.vaultTarget,
  });
  const connection = parseDriveConnection(value);
  if (!connection) {
    await markDriveRefreshFailure(tx, row.id, "drive credentials were missing or invalid");
    return null;
  }
  return { row, connection };
}

function shouldRefreshDriveConnection(row: DriveConnectionRow, connection: DriveConnection) {
  const expiresAtMs = earliestExpirationMs(row.expiresAt, connection.expiresAt);
  return expiresAtMs !== null && expiresAtMs <= Date.now() + DRIVE_REFRESH_SKEW_MS;
}

function sameDriveRefreshAttempt(a: DriveConnection, b: DriveConnection): boolean {
  return (
    a.accessToken === b.accessToken &&
    a.refreshToken === b.refreshToken &&
    a.expiresAt === b.expiresAt
  );
}

function earliestExpirationMs(
  rowExpiresAt: Date | string | null,
  secretExpiresAt: string | undefined,
) {
  const values = [
    rowExpiresAt instanceof Date
      ? rowExpiresAt.getTime()
      : typeof rowExpiresAt === "string"
        ? Date.parse(rowExpiresAt)
        : undefined,
    secretExpiresAt ? Date.parse(secretExpiresAt) : undefined,
  ].filter((value): value is number => typeof value === "number" && Number.isFinite(value));
  if (values.length === 0) return null;
  return Math.min(...values);
}

class DriveRefreshError extends Error {
  constructor(
    message: string,
    readonly permanent: boolean,
  ) {
    super(message);
    this.name = "DriveRefreshError";
  }
}

async function refreshDriveConnection(
  connection: DriveConnection,
  deps: ToolDeps,
): Promise<DriveConnection> {
  const clientId = deps.providerConfig?.GOOGLE_OAUTH_CLIENT_ID;
  const clientSecret = deps.providerConfig?.GOOGLE_OAUTH_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error("google oauth client credentials are not configured");
  }
  if (!connection.refreshToken) {
    throw new Error("drive refresh token is missing");
  }

  const response = await fetch(
    deps.providerConfig?.GOOGLE_OAUTH_TOKEN_ENDPOINT ?? GOOGLE_TOKEN_ENDPOINT,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      signal: AbortSignal.timeout(10_000),
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: "refresh_token",
        refresh_token: connection.refreshToken,
      }),
    },
  );
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok) {
    const error = typeof body.error === "string" ? body.error : `http_${response.status}`;
    throw new DriveRefreshError(
      `google refresh failed: ${error}`,
      permanentGoogleRefreshError(error),
    );
  }
  if (typeof body.access_token !== "string") {
    throw new Error("google refresh response missing access_token");
  }

  const refreshed: DriveConnection = {
    ...connection,
    accessToken: body.access_token,
  };
  if (typeof body.refresh_token === "string") refreshed.refreshToken = body.refresh_token;
  if (typeof body.expires_in === "number" && Number.isFinite(body.expires_in)) {
    refreshed.expiresAt = new Date(Date.now() + body.expires_in * 1000).toISOString();
  }
  if (typeof body.scope !== "string") {
    throw new DriveRefreshError("google refresh response missing scope", true);
  }
  validateRefreshedDriveScope(body.scope);
  refreshed.scope = body.scope;
  return refreshed;
}

async function markDriveRefreshFailure(
  tx: Tx,
  id: string,
  message: string,
  opts: { permanent?: boolean } = {},
): Promise<void> {
  await tx
    .update(workspaceOauthConnections)
    .set({
      ...(opts.permanent ? { status: "expired" } : {}),
      lastError: message.slice(0, 500),
    })
    .where(eq(workspaceOauthConnections.id, id));
}

function refreshErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "google refresh failed";
}

function permanentGoogleRefreshError(error: string): boolean {
  return new Set(["invalid_grant", "unauthorized_client", "invalid_client"]).has(error);
}

function isPermanentDriveRefreshError(error: unknown): boolean {
  return error instanceof DriveRefreshError && error.permanent;
}

function validateRefreshedDriveScope(scope: string): void {
  const scopes = scope
    .split(/\s+/)
    .map((value) => value.trim())
    .filter(Boolean);
  if (!scopes.includes(DRIVE_SCOPE) || scopes.some((value) => !allowedDriveScopes.has(value))) {
    throw new DriveRefreshError("google refresh returned unexpected Drive scopes", true);
  }
}

export const createToolRegistry = (
  adapters: Adapter[] = defaultAdapters,
): Map<string, AdapterTool> => buildToolRegistry(adapters);

export const registry: Map<string, AdapterTool> = createToolRegistry();

export const listTools = (toolRegistry: Map<string, AdapterTool> = registry): ToolDescriptor[] =>
  [...toolRegistry.values()].map((t) => t.descriptor);
