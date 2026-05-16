export type DefaultAudience = {
  name: string;
  description: string;
};

export const DEFAULT_AUDIENCES: ReadonlyArray<DefaultAudience> = [
  { name: "pact-admin", description: "Workspace admin console" },
  { name: "pact-audit", description: "Audit log readers" },
  { name: "pact-mcp", description: "MCP gateway access" },
  { name: "pact-gateway", description: "Pact gateway" },
  { name: "pact-agent", description: "Agent capability tokens" },
];
