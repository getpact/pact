import { createDriveAdapter, type DriveConnection } from "@getpact/adapter-drive";
import {
  type Adapter,
  type AdapterTool,
  buildToolRegistry,
  json,
  type ToolDescriptor,
} from "@getpact/adapter-sdk";
import { createSlackAdapter } from "@getpact/adapter-slack";
import { createClient, withWorkspace } from "@getpact/db";
import { auditEvents, policies, workspaceOauthConnections, workspaces } from "@getpact/db/schema";
import { loadSecretString } from "@getpact/vault";
import { and, desc, eq, isNull } from "drizzle-orm";

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

const driveAdapter = createDriveAdapter({
  loadConnection: async (ctx, deps) => {
    if (!deps.rawMek) return null;
    const db = createClient(deps.databaseUrl);
    const value = await withWorkspace(db, ctx.workspaceId, async (tx) => {
      const [connection] = await tx
        .select({
          vaultTarget: workspaceOauthConnections.vaultTarget,
          status: workspaceOauthConnections.status,
          expiresAt: workspaceOauthConnections.expiresAt,
        })
        .from(workspaceOauthConnections)
        .where(
          and(
            eq(workspaceOauthConnections.workspaceId, ctx.workspaceId),
            eq(workspaceOauthConnections.provider, "google_drive"),
            eq(workspaceOauthConnections.userId, ctx.userId),
            isNull(workspaceOauthConnections.disconnectedAt),
          ),
        )
        .limit(1);
      if (!connection || connection.status !== "connected") return null;
      if (connection.expiresAt && connection.expiresAt.getTime() <= Date.now()) return null;
      return loadSecretString(tx, deps.rawMek as Uint8Array, {
        workspaceId: ctx.workspaceId,
        kind: "google_drive_oauth",
        target: connection.vaultTarget,
      });
    });
    return parseDriveConnection(value);
  },
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

export const createToolRegistry = (
  adapters: Adapter[] = defaultAdapters,
): Map<string, AdapterTool> => buildToolRegistry(adapters);

export const registry: Map<string, AdapterTool> = createToolRegistry();

export const listTools = (toolRegistry: Map<string, AdapterTool> = registry): ToolDescriptor[] =>
  [...toolRegistry.values()].map((t) => t.descriptor);
