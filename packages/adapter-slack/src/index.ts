import {
  type Adapter,
  type AdapterContext,
  errorResult,
  json,
  type ToolDeps,
} from "@getpact/adapter-sdk";

export type SlackFetch = typeof fetch;

export type SlackClientOptions = {
  token: string;
  apiBaseUrl?: string;
  fetch?: SlackFetch;
};

export type SlackAuthTestResult = {
  ok: true;
  url?: string;
  team?: string;
  user?: string;
  teamId?: string;
  userId?: string;
  botId?: string;
};

export type SlackErrorResult = {
  ok: false;
  error: string;
};

export type SlackResult<T> = T | SlackErrorResult;

export type SlackChannel = {
  id: string;
  name?: string;
  isPrivate?: boolean;
  isMember?: boolean;
};

export type SlackConversationsListResult = {
  ok: true;
  channels: SlackChannel[];
  nextCursor: string | null;
};

export type SlackConversationsListInput = {
  limit?: number;
  cursor?: string;
  types?: string;
};

export type SlackClient = {
  authTest: () => Promise<SlackResult<SlackAuthTestResult>>;
  conversationsList: (
    input?: SlackConversationsListInput,
  ) => Promise<SlackResult<SlackConversationsListResult>>;
};

const defaultApiBaseUrl = "https://slack.com/api";
const allowedChannelTypes = new Set(["public_channel"]);

const requireString = (value: unknown, name: string): string | undefined => {
  if (typeof value === "string" && value.length > 0) return value;
  if (value === undefined || value === null) return undefined;
  throw new Error(`invalid Slack ${name}`);
};

const parseAuthTest = (value: unknown): SlackResult<SlackAuthTestResult> => {
  if (!value || typeof value !== "object") {
    throw new Error("invalid Slack response");
  }
  const body = value as Record<string, unknown>;
  if (body.ok === false) {
    return { ok: false, error: requireString(body.error, "error") ?? "unknown_error" };
  }
  if (body.ok !== true) throw new Error("invalid Slack response");
  const url = requireString(body.url, "url");
  const team = requireString(body.team, "team");
  const user = requireString(body.user, "user");
  const teamId = requireString(body.team_id, "team_id");
  const userId = requireString(body.user_id, "user_id");
  const botId = requireString(body.bot_id, "bot_id");
  return {
    ok: true,
    ...(url ? { url } : {}),
    ...(team ? { team } : {}),
    ...(user ? { user } : {}),
    ...(teamId ? { teamId } : {}),
    ...(userId ? { userId } : {}),
    ...(botId ? { botId } : {}),
  };
};

export type SlackAdapterOptions = {
  loadBotToken: (ctx: AdapterContext, deps: ToolDeps) => Promise<string | null>;
  createClient?: (token: string) => SlackClient;
};

const parseLimit = (value: unknown): number | undefined =>
  typeof value === "number" ? value : undefined;

const parseString = (value: unknown): string | undefined =>
  typeof value === "string" && value.length > 0 ? value : undefined;

const parseSafeChannelTypes = (value: unknown): string => {
  const parsed = parseString(value) ?? "public_channel";
  const types = parsed.split(",").map((v) => v.trim());
  if (types.every((type) => allowedChannelTypes.has(type))) return parsed;
  throw new Error("Slack channel types are restricted to public_channel");
};

export const createSlackAdapter = (opts: SlackAdapterOptions): Adapter => {
  const buildClient = opts.createClient ?? ((token: string) => createSlackClient({ token }));

  const loadClient = async (ctx: AdapterContext, deps: ToolDeps): Promise<SlackClient | null> => {
    if (!deps.rawMek) return null;
    const token = await opts.loadBotToken(ctx, deps);
    return token ? buildClient(token) : null;
  };

  return {
    name: "slack",
    tools: [
      {
        descriptor: {
          name: "pact.slack.auth.test",
          description: "Verify the workspace Slack bot token stored in Pact Vault.",
          inputSchema: { type: "object" },
        },
        handler: async (_args, ctx, deps) => {
          if (!deps.rawMek) return errorResult("MEK is not configured");
          const client = await loadClient(ctx, deps);
          if (!client) return errorResult("Slack bot token not found");
          return json(await client.authTest());
        },
      },
      {
        descriptor: {
          name: "pact.slack.channels.list",
          description: "List Slack channels visible to the workspace bot token (paginated).",
          inputSchema: {
            type: "object",
            properties: {
              limit: { type: "number" },
              cursor: { type: "string" },
              types: { type: "string", enum: ["public_channel"] },
            },
          },
        },
        handler: async (args, ctx, deps) => {
          if (!deps.rawMek) return errorResult("MEK is not configured");
          const client = await loadClient(ctx, deps);
          if (!client) return errorResult("Slack bot token not found");
          const input: SlackConversationsListInput = {};
          const limit = parseLimit(args.limit);
          const cursor = parseString(args.cursor);
          let types: string;
          try {
            types = parseSafeChannelTypes(args.types);
          } catch (e) {
            return errorResult(e instanceof Error ? e.message : "invalid Slack channel types");
          }
          if (limit !== undefined) input.limit = limit;
          if (cursor) input.cursor = cursor;
          input.types = types;
          return json(await client.conversationsList(input));
        },
      },
    ],
  };
};

const parseConversationsList = (value: unknown): SlackResult<SlackConversationsListResult> => {
  if (!value || typeof value !== "object") {
    throw new Error("invalid Slack response");
  }
  const body = value as Record<string, unknown>;
  if (body.ok === false) {
    return { ok: false, error: requireString(body.error, "error") ?? "unknown_error" };
  }
  if (body.ok !== true) throw new Error("invalid Slack response");
  const channelsRaw = Array.isArray(body.channels) ? body.channels : [];
  const channels: SlackChannel[] = [];
  for (const c of channelsRaw) {
    if (!c || typeof c !== "object") continue;
    const item = c as Record<string, unknown>;
    const id = requireString(item.id, "channel.id");
    if (!id) continue;
    const channel: SlackChannel = { id };
    const name = requireString(item.name, "channel.name");
    if (name) channel.name = name;
    if (typeof item.is_private === "boolean") channel.isPrivate = item.is_private;
    if (typeof item.is_member === "boolean") channel.isMember = item.is_member;
    channels.push(channel);
  }
  const meta = body.response_metadata as Record<string, unknown> | undefined;
  const cursorVal = meta?.next_cursor;
  const nextCursor = typeof cursorVal === "string" && cursorVal.length > 0 ? cursorVal : null;
  return { ok: true, channels, nextCursor };
};

export const createSlackClient = (opts: SlackClientOptions): SlackClient => {
  if (!opts.token) throw new Error("Slack token is required");
  if (/[\r\n\t]/.test(opts.token)) throw new Error("Slack token contains illegal whitespace");
  const fetchImpl = opts.fetch ?? fetch;
  const apiBaseUrl = opts.apiBaseUrl ?? defaultApiBaseUrl;

  const post = async (method: string, params: Record<string, string>): Promise<unknown> => {
    const res = await fetchImpl(`${apiBaseUrl}/${method}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${opts.token}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams(params).toString(),
    });
    return res.json();
  };

  return {
    async authTest() {
      return parseAuthTest(await post("auth.test", {}));
    },
    async conversationsList(input = {}) {
      const params: Record<string, string> = {};
      if (input.limit !== undefined) {
        const n = Math.max(1, Math.min(1000, Math.floor(input.limit)));
        params.limit = String(n);
      }
      if (input.cursor) params.cursor = input.cursor;
      if (input.types) params.types = input.types;
      return parseConversationsList(await post("conversations.list", params));
    },
  };
};
