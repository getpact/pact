import { parseDurationToSeconds } from "../duration.js";
import { listGroups } from "./group.js";

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
  multi: Map<string, string[]>;
  booleans: Set<string>;
};

export const parseFlags = (argv: readonly string[]): ParsedFlags => {
  const positional: string[] = [];
  const flags = new Map<string, string>();
  const multi = new Map<string, string[]>();
  const booleans = new Set<string>();
  const append = (name: string, value: string) => {
    const existing = multi.get(name);
    if (existing) {
      existing.push(value);
    } else {
      multi.set(name, [value]);
    }
    flags.set(name, value);
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i] ?? "";
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq >= 0) {
        append(a.slice(2, eq), a.slice(eq + 1));
        continue;
      }
      const name = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        append(name, next);
        i += 1;
      } else {
        booleans.add(name);
      }
      continue;
    }
    positional.push(a);
  }
  return { positional, flags, multi, booleans };
};

export type MintInviteInput = {
  email: string;
  groupIds: string[];
  scope: Record<string, unknown>;
  ttlSeconds: number;
};

export const mintInvite = async (
  input: MintInviteInput,
  opts: { apiBase: string; token: string; workspaceId: string },
): Promise<{ invite_id: string; token: string; accept_url: string }> => {
  const url = `${opts.apiBase}/v1/workspaces/${encodeURIComponent(opts.workspaceId)}/invites`;
  return requestJson("POST", url, opts.token, {
    email: input.email,
    group_ids: input.groupIds,
    scope: input.scope,
    ttl_seconds: input.ttlSeconds,
  });
};

const resolveGroupIds = async (
  groupNames: string[],
  opts: { apiBase: string; token: string; workspaceId: string },
): Promise<string[]> => {
  if (groupNames.length === 0) return [];
  const allUuids = groupNames.every((g) => /^[0-9a-fA-F-]{36}$/.test(g));
  if (allUuids) return groupNames;
  const list = await listGroups(opts);
  const ids: string[] = [];
  for (const ref of groupNames) {
    if (/^[0-9a-fA-F-]{36}$/.test(ref)) {
      ids.push(ref);
      continue;
    }
    const match = list.groups.find((g) => g.name === ref);
    if (!match) throw new Error(`group not found: ${ref}`);
    ids.push(match.id);
  }
  return ids;
};

const runMint = async (
  argv: readonly string[],
  io: { out: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const email = parsed.positional[0];
  if (!email) {
    throw new Error("usage: pact invite <email> [--group name]... [--scope json] [--ttl 7d]");
  }
  const groupNames = parsed.multi.get("group") ?? [];
  const scopeRaw = parsed.flags.get("scope");
  let scope: Record<string, unknown> = {};
  if (scopeRaw !== undefined) {
    const v = JSON.parse(scopeRaw) as unknown;
    if (!isRecord(v)) throw new Error("--scope must be a JSON object");
    scope = v;
  }
  const ttlRaw = parsed.flags.get("ttl") ?? "7d";
  const ttlSeconds = parseDurationToSeconds(ttlRaw);

  const base = apiBase(env);
  const token = adminToken(env);
  const wsId = workspaceId(env);
  const groupIds = await resolveGroupIds(groupNames, {
    apiBase: base,
    token,
    workspaceId: wsId,
  });
  const result = await mintInvite(
    { email, groupIds, scope, ttlSeconds },
    { apiBase: base, token, workspaceId: wsId },
  );
  io.out(`invite ${result.invite_id} minted for ${email}\n`);
  io.out(`accept url: ${result.accept_url}\n`);
};

export type RunResult = { exitCode: number };

export const runInvite = async (
  argv: readonly string[],
  io: { out: (s: string) => void; err: (s: string) => void } = {
    out: (s) => process.stdout.write(s),
    err: (s) => process.stderr.write(s),
  },
  env: NodeJS.ProcessEnv = process.env,
): Promise<RunResult> => {
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    io.err(
      [
        "usage: pact invite <email> [--group name]... [--scope json] [--ttl 7d|24h|3600]",
        "",
        "env:",
        "  PACT_ADMIN_TOKEN  admin bearer token",
        "  PACT_WORKSPACE_ID workspace id",
        "  PACT_API_BASE     admin api base (default https://issuer.getpact.dev)",
        "",
      ].join("\n"),
    );
    return { exitCode: argv.length === 0 ? 1 : 0 };
  }
  try {
    await runMint(argv, io, env);
    return { exitCode: 0 };
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
