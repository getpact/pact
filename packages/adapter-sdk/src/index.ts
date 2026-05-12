export type ToolContent = { type: "text"; text: string };

export type ToolResult = {
  content: ToolContent[];
  isError?: boolean;
};

export type ToolDescriptor = {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties?: Record<string, unknown>;
    required?: string[];
  };
};

export type AdapterContext = {
  workspaceId: string;
  userId: string;
  email: string;
  groups: string[];
  roles: string[];
};

export type ToolDeps = {
  databaseUrl: string;
  rawMek?: Uint8Array;
  providerConfig?: Record<string, string | undefined>;
};

export type AdapterToolHandler = (
  args: Record<string, unknown>,
  ctx: AdapterContext,
  deps: ToolDeps,
) => Promise<ToolResult>;

export type ToolAuthorization = {
  action: string;
  resource: string;
};

export type AdapterToolAuthorizer = (
  args: Record<string, unknown>,
  ctx: AdapterContext,
) => ToolAuthorization;

export type AdapterTool = {
  descriptor: ToolDescriptor;
  authorize?: AdapterToolAuthorizer;
  handler: AdapterToolHandler;
};

export type Adapter = {
  name: string;
  tools: AdapterTool[];
};

export const json = (value: unknown): ToolResult => ({
  content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
});

export const errorResult = (message: string): ToolResult => ({
  content: [{ type: "text", text: message }],
  isError: true,
});

export const defaultToolAuthorization = (toolName: string): ToolAuthorization => ({
  action: `tool:${toolName}`,
  resource: `tool:${toolName}`,
});

export const buildToolRegistry = (adapters: Adapter[]): Map<string, AdapterTool> => {
  const registry = new Map<string, AdapterTool>();
  for (const adapter of adapters) {
    for (const tool of adapter.tools) {
      if (registry.has(tool.descriptor.name)) {
        throw new Error(
          `duplicate tool name: ${tool.descriptor.name} (in adapter ${adapter.name})`,
        );
      }
      registry.set(tool.descriptor.name, tool);
    }
  }
  return registry;
};
