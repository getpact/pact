import { createClient, withWorkspace } from "@getpact/db";
import { auditEvents, policies, workspaces } from "@getpact/db/schema";
import { and, desc, eq, isNull } from "drizzle-orm";
import type { AuthContext } from "./auth.js";

export type ToolDescriptor = {
  name: string;
  description: string;
  inputSchema: { type: "object"; properties?: Record<string, unknown>; required?: string[] };
};

export type ToolResult = {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
};

export type ToolDeps = {
  databaseUrl: string;
};

export type ToolHandler = (
  args: Record<string, unknown>,
  ctx: AuthContext,
  deps: ToolDeps,
) => Promise<ToolResult>;

export type Tool = {
  descriptor: ToolDescriptor;
  handler: ToolHandler;
};

const json = (value: unknown): ToolResult => ({
  content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
});

const whoami: Tool = {
  descriptor: {
    name: "pact.whoami",
    description: "Return the verified identity, groups, and roles for the current Pact JWT.",
    inputSchema: { type: "object" },
  },
  handler: async (_args, ctx) =>
    json({
      workspaceId: ctx.workspaceId,
      userId: ctx.userId,
      email: ctx.email,
      groups: ctx.groups,
      roles: ctx.roles,
    }),
};

const workspaceInfo: Tool = {
  descriptor: {
    name: "pact.workspace.info",
    description: "Return the workspace metadata visible to the current token.",
    inputSchema: { type: "object" },
  },
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

const auditRecent: Tool = {
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
  handler: async (args, ctx, deps) => {
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

const policyActive: Tool = {
  descriptor: {
    name: "pact.policy.active",
    description: "Return the active policy version body for the current workspace.",
    inputSchema: { type: "object" },
  },
  handler: async (_args, ctx, deps) => {
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

export const registry: Map<string, Tool> = new Map([
  [whoami.descriptor.name, whoami],
  [workspaceInfo.descriptor.name, workspaceInfo],
  [auditRecent.descriptor.name, auditRecent],
  [policyActive.descriptor.name, policyActive],
]);

export const listTools = (): ToolDescriptor[] => [...registry.values()].map((t) => t.descriptor);
