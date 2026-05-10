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

export type SlackClient = {
  authTest: () => Promise<SlackResult<SlackAuthTestResult>>;
};

const defaultApiBaseUrl = "https://slack.com/api";

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

export const createSlackClient = (opts: SlackClientOptions): SlackClient => {
  if (!opts.token) throw new Error("Slack token is required");
  const fetchImpl = opts.fetch ?? fetch;
  const apiBaseUrl = opts.apiBaseUrl ?? defaultApiBaseUrl;

  return {
    async authTest() {
      const res = await fetchImpl(`${apiBaseUrl}/auth.test`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${opts.token}`,
          "content-type": "application/x-www-form-urlencoded",
        },
      });
      const body = await res.json();
      return parseAuthTest(body);
    },
  };
};
