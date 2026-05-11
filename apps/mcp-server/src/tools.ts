import {
  type Adapter,
  type AdapterTool,
  buildToolRegistry,
  json,
  type ToolDescriptor,
} from "@getpact/adapter-sdk";
import { createSlackAdapter } from "@getpact/adapter-slack";
import { createClient, withWorkspace } from "@getpact/db";
import { auditEvents, policies, workspaces } from "@getpact/db/schema";
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
    action: "pact.whoami",
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
    action: "pact.workspace.info",
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
    action: "pact.audit.recent",
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
    action: "pact.policy.active",
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

const defaultAdapters: Adapter[] = [pactAdapter, slackAdapter];

export const createToolRegistry = (
  adapters: Adapter[] = defaultAdapters,
): Map<string, AdapterTool> => buildToolRegistry(adapters);

export const registry: Map<string, AdapterTool> = createToolRegistry();

export const listTools = (toolRegistry: Map<string, AdapterTool> = registry): ToolDescriptor[] =>
  [...toolRegistry.values()].map((t) => t.descriptor);
