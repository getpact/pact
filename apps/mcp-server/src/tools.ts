import {
  createDriveAdapter,
  createDriveClient,
  type DriveConnection,
  type DriveFile,
} from "@getpact/adapter-drive";
import {
  type Adapter,
  type AdapterContext,
  type AdapterTool,
  buildToolRegistry,
  json,
  type ToolDeps,
  type ToolDescriptor,
} from "@getpact/adapter-sdk";
import { createClient, type Tx, withWorkspace } from "@getpact/db";
import {
  auditEvents,
  driveDocumentChunks,
  policies,
  workspaceOauthConnections,
  workspaces,
} from "@getpact/db/schema";
import { databaseRateLimiter } from "@getpact/ratelimit";
import { loadSecretString, storeSecret } from "@getpact/vault";
import { and, desc, eq, isNull, sql } from "drizzle-orm";
import { brainAdapter } from "./tools/brain.js";

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

const DRIVE_PROVIDER = "google_drive";
const DRIVE_SECRET_KIND = "google_drive_oauth";
const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.readonly";
const DRIVE_REFRESH_SKEW_MS = 5 * 60_000;
const DRIVE_INDEX_DEFAULT_CHUNK_CHARS = 1200;
const DRIVE_INDEX_MAX_CHUNK_CHARS = 4000;
const DRIVE_INDEX_MAX_CHUNKS = 80;
const DRIVE_INDEX_MAX_CHARS = 250_000;
const DRIVE_INDEX_FILE_RATE_LIMIT = 10;
const DRIVE_INDEX_USER_RATE_LIMIT = 30;
const DRIVE_INDEX_RATE_WINDOW_SECONDS = 10 * 60;
const DRIVE_SEARCH_RATE_LIMIT = 60;
const DRIVE_SEARCH_RATE_WINDOW_SECONDS = 10 * 60;
const DRIVE_SEARCH_MAX_QUERY_CHARS = 200;
const DRIVE_SEARCH_MAX_LIMIT = 20;
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

const driveFileIndex: AdapterTool = {
  descriptor: {
    name: "pact.drive.file.index",
    description: "Export a Google Drive file, chunk it, and store snippets for retrieval.",
    inputSchema: {
      type: "object",
      required: ["fileId"],
      properties: {
        fileId: { type: "string" },
        mimeType: { type: "string", enum: ["text/plain", "text/markdown"] },
        maxChars: { type: "number", minimum: 1000, maximum: DRIVE_INDEX_MAX_CHARS },
        chunkChars: { type: "number", minimum: 400, maximum: DRIVE_INDEX_MAX_CHUNK_CHARS },
      },
    },
  },
  authorize: (input, ctx) => {
    const fileId = stringInput(input, "fileId");
    return {
      action: "drive.file.index",
      resource: `workspace:${ctx.workspaceId}:drive:user:${ctx.userId}:file:${isSafeDriveFileId(fileId) ? fileId : "invalid"}`,
    };
  },
  async handler(input, ctx, deps) {
    const fileId = stringInput(input, "fileId");
    if (!isSafeDriveFileId(fileId)) {
      return { content: [{ type: "text", text: "valid fileId is required" }], isError: true };
    }

    const connection = await loadDriveConnection(ctx, deps);
    if (!connection?.accessToken) {
      return {
        content: [{ type: "text", text: "Google Drive is not connected for this user." }],
        isError: true,
      };
    }

    const maxChars = clampNumber(
      numberInput(input, "maxChars"),
      1_000,
      DRIVE_INDEX_MAX_CHARS,
      80_000,
    );
    const chunkChars = clampNumber(
      numberInput(input, "chunkChars"),
      400,
      DRIVE_INDEX_MAX_CHUNK_CHARS,
      DRIVE_INDEX_DEFAULT_CHUNK_CHARS,
    );
    const mimeType = stringInput(input, "mimeType") ?? "text/plain";
    const client = createDriveClient({ accessToken: connection.accessToken });
    const rate = await hitDriveIndexRateLimit(deps.databaseUrl, ctx, fileId);
    if (!rate.allowed) {
      return {
        content: [{ type: "text", text: "Drive indexing rate limit exceeded. Try again later." }],
        isError: true,
      };
    }
    const metadata = await client.getFile({ fileId });
    const exported = await client.exportText({ fileId, mimeType });
    const text = exported.slice(0, maxChars);
    const chunks = chunkText(text, chunkChars).slice(0, DRIVE_INDEX_MAX_CHUNKS);
    const db = createClient(deps.databaseUrl);
    const now = new Date();
    const modifiedTime = parseOptionalDate(metadata.modifiedTime);
    const fileName = cleanMetadataString(metadata.name, 300);

    await withWorkspace(db, ctx.workspaceId, async (tx) => {
      await tx
        .delete(driveDocumentChunks)
        .where(
          and(
            eq(driveDocumentChunks.workspaceId, ctx.workspaceId),
            eq(driveDocumentChunks.userId, ctx.userId),
            eq(driveDocumentChunks.fileId, fileId),
          ),
        );
      if (chunks.length === 0) return;
      await tx.insert(driveDocumentChunks).values(
        await Promise.all(
          chunks.map(async (chunk, index) => ({
            workspaceId: ctx.workspaceId,
            userId: ctx.userId,
            fileId,
            fileName: fileName ?? null,
            mimeType: metadata.mimeType ?? mimeType,
            modifiedTime,
            chunkIndex: index,
            content: chunk,
            contentSha256: await sha256Hex(chunk),
            indexedAt: now,
          })),
        ),
      );
    });

    return json({
      fileId,
      fileName,
      chunks: chunks.length,
      indexedChars: chunks.reduce((sum, chunk) => sum + chunk.length, 0),
      truncated: exported.length > text.length || chunks.length === DRIVE_INDEX_MAX_CHUNKS,
      rateLimit: {
        remaining: rate.remaining,
        resetAt: new Date(rate.resetAt).toISOString(),
      },
    });
  },
};

const driveSearch: AdapterTool = {
  descriptor: {
    name: "pact.drive.search",
    description: "Search indexed Google Drive chunks for agent context.",
    inputSchema: {
      type: "object",
      required: ["query"],
      properties: {
        query: { type: "string" },
        limit: { type: "number", minimum: 1, maximum: DRIVE_SEARCH_MAX_LIMIT },
      },
    },
  },
  authorize: (_input, ctx) => {
    return {
      action: "drive.search",
      resource: `workspace:${ctx.workspaceId}:drive:user:${ctx.userId}:search`,
    };
  },
  async handler(input, ctx, deps) {
    const query = stringInput(input, "query")?.trim().slice(0, DRIVE_SEARCH_MAX_QUERY_CHARS);
    if (!query) {
      return { content: [{ type: "text", text: "query is required" }], isError: true };
    }
    const rate = await hitDriveSearchRateLimit(deps.databaseUrl, ctx);
    if (!rate.allowed) {
      return {
        content: [{ type: "text", text: "Drive search rate limit exceeded. Try again later." }],
        isError: true,
      };
    }
    const connection = await loadDriveConnection(ctx, deps);
    if (!connection?.accessToken) {
      return {
        content: [{ type: "text", text: "Google Drive is not connected for this user." }],
        isError: true,
      };
    }
    const limit = clampNumber(numberInput(input, "limit"), 1, DRIVE_SEARCH_MAX_LIMIT, 5);
    const db = createClient(deps.databaseUrl);
    const rows = (await withWorkspace(db, ctx.workspaceId, (tx) =>
      tx.execute(sql`
        SELECT file_id AS "fileId",
               file_name AS "fileName",
               mime_type AS "mimeType",
               chunk_index AS "chunkIndex",
               content,
               indexed_at AS "indexedAt",
               ts_rank_cd(to_tsvector('english', content), websearch_to_tsquery('english', ${query})) AS rank
        FROM drive_document_chunks
        WHERE workspace_id = ${ctx.workspaceId}
          AND user_id = ${ctx.userId}
          AND to_tsvector('english', content) @@ websearch_to_tsquery('english', ${query})
        ORDER BY rank DESC, indexed_at DESC
        LIMIT ${limit}
      `),
    )) as Array<{
      fileId: string;
      fileName: string | null;
      mimeType: string | null;
      chunkIndex: number;
      content: string;
      indexedAt: Date | string;
      rank: number;
    }>;
    const accessibleRows = await filterAccessibleDriveRows(
      createDriveClient({ accessToken: connection.accessToken }),
      rows,
    );

    return json({
      query,
      rateLimit: {
        remaining: rate.remaining,
        resetAt: new Date(rate.resetAt).toISOString(),
      },
      results: accessibleRows.map(({ row, metadata }) => ({
        fileId: row.fileId,
        fileName: metadata.name ?? row.fileName,
        mimeType: metadata.mimeType ?? row.mimeType,
        chunkIndex: row.chunkIndex,
        snippet: snippetFor(row.content, query),
        rank: row.rank,
        indexedAt: formatTimestamp(row.indexedAt),
      })),
    });
  },
};

const driveRagAdapter: Adapter = {
  name: "google-drive-rag",
  tools: [driveFileIndex, driveSearch],
};

const defaultAdapters: Adapter[] = [pactAdapter, driveAdapter, brainAdapter];

export function isDriveRagEnabled(providerConfig?: Record<string, string | undefined>): boolean {
  return providerConfig?.DRIVE_RAG_ENABLED === "true";
}

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

function stringInput(input: unknown, key: string): string | undefined {
  if (!input || typeof input !== "object") return undefined;
  const value = (input as Record<string, unknown>)[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberInput(input: unknown, key: string): number | undefined {
  if (!input || typeof input !== "object") return undefined;
  const value = (input as Record<string, unknown>)[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function clampNumber(
  value: number | undefined,
  min: number,
  max: number,
  fallback: number,
): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(value)));
}

function isSafeDriveFileId(fileId: string | undefined): fileId is string {
  return !!fileId && /^[A-Za-z0-9_-]+$/.test(fileId);
}

function parseOptionalDate(value: string | undefined): Date | null {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms) : null;
}

function cleanMetadataString(value: string | undefined, max: number): string | undefined {
  if (!value) return undefined;
  const cleaned = [...value]
    .map((char) => {
      const code = char.charCodeAt(0);
      return code < 32 || code === 127 ? " " : char;
    })
    .join("")
    .trim()
    .slice(0, max);
  return cleaned.length > 0 ? cleaned : undefined;
}

async function hitDriveIndexRateLimit(
  databaseUrl: string,
  ctx: AdapterContext,
  fileId: string,
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
  const limiter = databaseRateLimiter(databaseUrl);
  const [user, file] = await Promise.all([
    limiter.hit(
      `mcp::drive-index::${ctx.workspaceId}::${ctx.userId}`,
      DRIVE_INDEX_USER_RATE_LIMIT,
      DRIVE_INDEX_RATE_WINDOW_SECONDS,
    ),
    limiter.hit(
      `mcp::drive-index::${ctx.workspaceId}::${ctx.userId}::${fileId}`,
      DRIVE_INDEX_FILE_RATE_LIMIT,
      DRIVE_INDEX_RATE_WINDOW_SECONDS,
    ),
  ]);
  return {
    allowed: user.allowed && file.allowed,
    remaining: Math.min(user.remaining, file.remaining),
    resetAt: Math.max(user.resetAt, file.resetAt),
  };
}

async function hitDriveSearchRateLimit(
  databaseUrl: string,
  ctx: AdapterContext,
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
  return databaseRateLimiter(databaseUrl).hit(
    `mcp::drive-search::${ctx.workspaceId}::${ctx.userId}`,
    DRIVE_SEARCH_RATE_LIMIT,
    DRIVE_SEARCH_RATE_WINDOW_SECONDS,
  );
}

function chunkText(input: string, chunkChars: number): string[] {
  const normalized = input.replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim();
  if (!normalized) return [];
  const chunks: string[] = [];
  let cursor = 0;
  while (cursor < normalized.length && chunks.length < DRIVE_INDEX_MAX_CHUNKS) {
    const target = Math.min(normalized.length, cursor + chunkChars);
    const nextBreak = normalized.lastIndexOf("\n\n", target);
    const end = nextBreak > cursor + Math.floor(chunkChars * 0.5) ? nextBreak : target;
    const chunk = normalized.slice(cursor, end).trim();
    if (chunk) chunks.push(chunk);
    cursor = end;
    while (cursor < normalized.length && /\s/.test(normalized[cursor] ?? "")) cursor++;
  }
  return chunks;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function formatTimestamp(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

async function filterAccessibleDriveRows<T extends { fileId: string }>(
  client: ReturnType<typeof createDriveClient>,
  rows: T[],
): Promise<Array<{ row: T; metadata: DriveFile }>> {
  const metadataByFile = new Map<string, DriveFile | null>();
  const fileIds = [...new Set(rows.map((row) => row.fileId))];
  await Promise.all(
    fileIds.map(async (fileId) => {
      try {
        metadataByFile.set(fileId, await client.getFile({ fileId }));
      } catch (e) {
        const message = e instanceof Error ? e.message : "";
        if (message.includes("(403)") || message.includes("(404)")) {
          metadataByFile.set(fileId, null);
          return;
        }
        throw e;
      }
    }),
  );
  return rows.flatMap((row) => {
    const metadata = metadataByFile.get(row.fileId);
    return metadata ? [{ row, metadata }] : [];
  });
}

function snippetFor(content: string, query: string): string {
  const terms = query
    .toLowerCase()
    .split(/\s+/)
    .map((term) => term.replace(/[^a-z0-9_-]/g, ""))
    .filter(Boolean);
  const lower = content.toLowerCase();
  const hits = terms.map((term) => lower.indexOf(term)).filter((idx) => idx >= 0);
  const anchor =
    hits.length > 1 ? Math.floor((Math.min(...hits) + Math.max(...hits)) / 2) : (hits[0] ?? 0);
  const start = Math.max(0, anchor - 240);
  const end = Math.min(content.length, anchor + 360);
  return content.slice(start, end).trim();
}

export const createToolRegistry = (
  adapters: Adapter[] = defaultAdapters,
): Map<string, AdapterTool> => buildToolRegistry(adapters);

export const createConfiguredToolRegistry = (
  providerConfig?: Record<string, string | undefined>,
): Map<string, AdapterTool> =>
  createToolRegistry([
    ...defaultAdapters,
    ...(isDriveRagEnabled(providerConfig) ? [driveRagAdapter] : []),
  ]);

export const registry: Map<string, AdapterTool> = createConfiguredToolRegistry();

export const listTools = (toolRegistry: Map<string, AdapterTool> = registry): ToolDescriptor[] =>
  [...toolRegistry.values()].map((t) => t.descriptor);
