const DEFAULT_API_BASE = "https://issuer.getpact.dev";

export type ApiError = {
  status: number;
  code: string;
  message: string;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const apiBase = (env: NodeJS.ProcessEnv = process.env): string =>
  (env.PACT_ADMIN_API_BASE ?? env.PACT_API_BASE ?? DEFAULT_API_BASE).replace(/\/+$/, "");

const adminToken = (env: NodeJS.ProcessEnv = process.env): string => {
  const t = env.PACT_ADMIN_TOKEN;
  if (!t || t.length === 0) {
    throw new Error("missing PACT_ADMIN_TOKEN");
  }
  return t;
};

const workspaceId = (env: NodeJS.ProcessEnv = process.env): string => {
  const w = env.PACT_WORKSPACE_ID;
  if (!w || w.length === 0) {
    throw new Error("missing PACT_WORKSPACE_ID");
  }
  return w;
};

export class CliApiError extends Error {
  status: number;
  code: string;
  constructor(err: ApiError) {
    super(err.message);
    this.name = "CliApiError";
    this.status = err.status;
    this.code = err.code;
  }
}

const parseErrorBody = async (res: Response): Promise<ApiError> => {
  let code = `http_${res.status}`;
  let message = res.statusText || "request failed";
  try {
    const body = (await res.json()) as unknown;
    if (isRecord(body)) {
      if (typeof body.error === "string") code = body.error;
      else if (typeof body.code === "string") code = body.code;
      if (typeof body.message === "string") message = body.message;
    }
  } catch {}
  if (res.status === 401 && code === `http_${res.status}`) {
    code = "unauthorized";
    message = "admin token invalid or expired";
  }
  return { status: res.status, code, message };
};

const requestJson = async <T>(
  method: string,
  url: string,
  token: string,
  body?: unknown,
): Promise<T> => {
  const headers: Record<string, string> = {
    authorization: `Bearer ${token}`,
    accept: "application/json",
  };
  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const res = await fetch(url, init);
  if (!res.ok) throw new CliApiError(await parseErrorBody(res));
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
};

export type ParsedFlags = {
  positional: string[];
  flags: Map<string, string>;
  booleans: Set<string>;
};

export const parseFlags = (argv: readonly string[]): ParsedFlags => {
  const positional: string[] = [];
  const flags = new Map<string, string>();
  const booleans = new Set<string>();
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i] ?? "";
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq >= 0) {
        flags.set(a.slice(2, eq), a.slice(eq + 1));
        continue;
      }
      const name = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags.set(name, next);
        i += 1;
      } else {
        booleans.add(name);
      }
      continue;
    }
    positional.push(a);
  }
  return { positional, flags, booleans };
};

export type Group = {
  id: string;
  name: string;
  description: string | null;
  created_at: string;
  revoked_at: string | null;
};

export const createGroup = async (
  name: string,
  opts: { apiBase: string; token: string; workspaceId: string; description?: string },
): Promise<{ group: Group }> => {
  const url = `${opts.apiBase}/v1/workspaces/${encodeURIComponent(opts.workspaceId)}/groups`;
  const body: Record<string, unknown> = { name };
  if (opts.description !== undefined) body.description = opts.description;
  return requestJson("POST", url, opts.token, body);
};

export const listGroups = async (opts: {
  apiBase: string;
  token: string;
  workspaceId: string;
}): Promise<{ groups: Group[] }> => {
  const url = `${opts.apiBase}/v1/workspaces/${encodeURIComponent(opts.workspaceId)}/groups`;
  return requestJson("GET", url, opts.token);
};

const resolveGroupId = async (
  identifier: string,
  opts: { apiBase: string; token: string; workspaceId: string },
): Promise<string> => {
  if (/^[0-9a-fA-F-]{36}$/.test(identifier)) return identifier;
  const list = await listGroups(opts);
  const match = list.groups.find((g) => g.name === identifier);
  if (!match) throw new Error(`group not found: ${identifier}`);
  return match.id;
};

export const addGroupMember = async (
  groupId: string,
  userRef: string,
  opts: { apiBase: string; token: string; workspaceId: string },
): Promise<unknown> => {
  const url = `${opts.apiBase}/v1/workspaces/${encodeURIComponent(opts.workspaceId)}/groups/${encodeURIComponent(groupId)}/members`;
  const body: Record<string, unknown> = /^[0-9a-fA-F-]{36}$/.test(userRef)
    ? { user_id: userRef }
    : { email: userRef };
  return requestJson("POST", url, opts.token, body);
};

export const removeGroupMember = async (
  groupId: string,
  userId: string,
  opts: { apiBase: string; token: string; workspaceId: string },
): Promise<unknown> => {
  const url = `${opts.apiBase}/v1/workspaces/${encodeURIComponent(opts.workspaceId)}/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}`;
  return requestJson("DELETE", url, opts.token);
};

const formatGroupTable = (rows: Group[]): string => {
  if (rows.length === 0) return "no groups\n";
  const headers = ["ID", "NAME", "DESCRIPTION", "CREATED"];
  const data = rows.map((r) => [r.id, r.name, r.description ?? "", r.created_at]);
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...data.map((row) => (row[i] ?? "").length)),
  );
  const fmt = (cells: string[]): string =>
    cells.map((c, i) => c.padEnd(widths[i] ?? c.length)).join("  ");
  const lines = [fmt(headers), fmt(widths.map((w) => "-".repeat(w)))];
  for (const row of data) lines.push(fmt(row));
  return `${lines.join("\n")}\n`;
};

const runCreate = async (
  argv: readonly string[],
  io: { out: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const name = parsed.positional[0];
  if (!name) throw new Error("usage: pact group create <name> [--description text]");
  const description = parsed.flags.get("description");
  const base = apiBase(env);
  const token = adminToken(env);
  const wsId = workspaceId(env);
  const result = await createGroup(name, {
    apiBase: base,
    token,
    workspaceId: wsId,
    ...(description !== undefined ? { description } : {}),
  });
  io.out(`created group ${result.group.name} (${result.group.id})\n`);
};

const runList = async (
  argv: readonly string[],
  io: { out: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const format = parsed.flags.get("format") ?? "table";
  const base = apiBase(env);
  const token = adminToken(env);
  const wsId = workspaceId(env);
  const result = await listGroups({ apiBase: base, token, workspaceId: wsId });
  if (format === "json") {
    io.out(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  io.out(formatGroupTable(result.groups));
};

const runAddMember = async (
  argv: readonly string[],
  io: { out: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const groupRef = parsed.positional[0];
  const userRef = parsed.positional[1];
  if (!groupRef || !userRef) {
    throw new Error("usage: pact group add-member <group> <user-email-or-id>");
  }
  const base = apiBase(env);
  const token = adminToken(env);
  const wsId = workspaceId(env);
  const groupId = await resolveGroupId(groupRef, { apiBase: base, token, workspaceId: wsId });
  await addGroupMember(groupId, userRef, { apiBase: base, token, workspaceId: wsId });
  io.out(`added ${userRef} to group ${groupRef}\n`);
};

const runRemoveMember = async (
  argv: readonly string[],
  io: { out: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const groupRef = parsed.positional[0];
  const userId = parsed.positional[1];
  if (!groupRef || !userId) {
    throw new Error("usage: pact group remove-member <group> <user-id>");
  }
  const base = apiBase(env);
  const token = adminToken(env);
  const wsId = workspaceId(env);
  const groupId = await resolveGroupId(groupRef, { apiBase: base, token, workspaceId: wsId });
  await removeGroupMember(groupId, userId, { apiBase: base, token, workspaceId: wsId });
  io.out(`removed ${userId} from group ${groupRef}\n`);
};

export type RunResult = { exitCode: number };

export const runGroup = async (
  argv: readonly string[],
  io: { out: (s: string) => void; err: (s: string) => void } = {
    out: (s) => process.stdout.write(s),
    err: (s) => process.stderr.write(s),
  },
  env: NodeJS.ProcessEnv = process.env,
): Promise<RunResult> => {
  const sub = argv[0];
  const rest = argv.slice(1);
  try {
    switch (sub) {
      case "create":
        await runCreate(rest, io, env);
        return { exitCode: 0 };
      case "list":
        await runList(rest, io, env);
        return { exitCode: 0 };
      case "add-member":
        await runAddMember(rest, io, env);
        return { exitCode: 0 };
      case "remove-member":
        await runRemoveMember(rest, io, env);
        return { exitCode: 0 };
      default:
        io.err(
          [
            "usage: pact group create <name> [--description text]",
            "       pact group list [--format json|table]",
            "       pact group add-member <group> <user-email-or-id>",
            "       pact group remove-member <group> <user-id>",
            "",
            "env:",
            "  PACT_ADMIN_TOKEN  admin bearer token",
            "  PACT_WORKSPACE_ID workspace id",
            "  PACT_API_BASE     admin api base (default https://issuer.getpact.dev)",
            "",
          ].join("\n"),
        );
        return { exitCode: 1 };
    }
  } catch (e) {
    if (e instanceof CliApiError) {
      io.err(`error: ${e.code}: ${e.message} (status ${e.status})\n`);
    } else {
      const msg = e instanceof Error ? e.message : String(e);
      io.err(`error: ${msg}\n`);
    }
    return { exitCode: 1 };
  }
};
