import { defaultToolAuthorization } from "@getpact/adapter-sdk";
import type { AuthContext } from "./auth.js";
import { createConfiguredToolRegistry, listTools, type Tool, type ToolDeps } from "./tools.js";
import type { VerifyClient } from "./verify-client.js";

type JsonRpcRequest = {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
};

type JsonRpcResponse = {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
};

const ok = (id: string | number | null, result: unknown): JsonRpcResponse => ({
  jsonrpc: "2.0",
  id,
  result,
});

const err = (
  id: string | number | null,
  code: number,
  message: string,
  data?: unknown,
): JsonRpcResponse => ({
  jsonrpc: "2.0",
  id,
  error: data === undefined ? { code, message } : { code, message, data },
});

export type HandleOptions = {
  audience: string;
  verify?: VerifyClient;
  deps: ToolDeps;
  registry?: Map<string, Tool>;
};

export const handleMcp = async (
  body: JsonRpcRequest,
  ctx: AuthContext,
  opts: HandleOptions,
): Promise<JsonRpcResponse> => {
  const id = body.id ?? null;
  const toolRegistry = opts.registry ?? createConfiguredToolRegistry(opts.deps.providerConfig);
  switch (body.method) {
    case "initialize":
      return ok(id, {
        protocolVersion: "2024-11-05",
        serverInfo: { name: "pact-mcp", version: "0.0.0" },
        capabilities: { tools: { listChanged: false } },
      });

    case "tools/list":
      return ok(id, { tools: listTools(toolRegistry) });

    case "tools/call": {
      const params = body.params ?? {};
      const name = params.name as string | undefined;
      const args = (params.arguments as Record<string, unknown> | undefined) ?? {};
      if (!name) return err(id, -32602, "missing tool name");
      const tool = toolRegistry.get(name);
      if (!tool) return err(id, -32601, `unknown tool: ${name}`);

      const authorization = tool.authorize?.(args, ctx) ?? defaultToolAuthorization(name);
      if (!opts.verify) {
        return err(id, -32002, "verifier unavailable");
      }

      {
        let verdict: Awaited<ReturnType<VerifyClient>>;
        try {
          verdict = await opts.verify({
            token: ctx.token,
            action: authorization.action,
            resource: authorization.resource,
            audience: opts.audience,
          });
        } catch {
          return err(id, -32002, "verification failed");
        }
        if (!verdict.allow) {
          return err(id, -32001, "denied", { reasons: verdict.reasons });
        }
      }

      try {
        const result = await tool.handler(args, ctx, opts.deps);
        return ok(id, result);
      } catch (e) {
        const msg = e instanceof Error ? e.message : "tool failure";
        return err(id, -32000, msg);
      }
    }

    default:
      return err(id, -32601, `unknown method: ${body.method}`);
  }
};
