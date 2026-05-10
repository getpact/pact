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

export type ToolHandler = (args: Record<string, unknown>, ctx: AuthContext) => Promise<ToolResult>;

export type Tool = {
  descriptor: ToolDescriptor;
  handler: ToolHandler;
};

const whoami: Tool = {
  descriptor: {
    name: "pact.whoami",
    description: "Return the verified identity, groups, and roles for the current Pact JWT.",
    inputSchema: { type: "object" },
  },
  handler: async (_args, ctx) => ({
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            workspaceId: ctx.workspaceId,
            userId: ctx.userId,
            email: ctx.email,
            groups: ctx.groups,
            roles: ctx.roles,
          },
          null,
          2,
        ),
      },
    ],
  }),
};

export const registry: Map<string, Tool> = new Map([[whoami.descriptor.name, whoami]]);

export const listTools = (): ToolDescriptor[] => [...registry.values()].map((t) => t.descriptor);
