const DEFAULT_API_BASE = "https://issuer.getpact.dev";
const REASON_MAX = 280;

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
  } catch {
    // body is not json; keep defaults
  }
  if (res.status === 401 && code === `http_${res.status}`) {
    code = "unauthorized";
    message = "admin token invalid or expired";
  }
  return { status: res.status, code, message };
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
  if (!res.ok) {
    throw new CliApiError(await parseErrorBody(res));
  }
  if (res.status === 204) {
    return undefined as T;
  }
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

const requireFlag = (parsed: ParsedFlags, name: string): string => {
  const v = parsed.flags.get(name);
  if (v === undefined || v.length === 0) {
    throw new Error(`missing required flag --${name}`);
  }
  return v;
};

const optionalInt = (parsed: ParsedFlags, name: string): number | undefined => {
  const v = parsed.flags.get(name);
  if (v === undefined) return undefined;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) {
    throw new Error(`flag --${name} must be an integer`);
  }
  return n;
};

export type SendCap = {
  id: string;
  workspace_id: string;
  issuer_user_id: string;
  grantee_user_id: string;
  scope_pattern: unknown;
  max_uses: number | null;
  used_count: number;
  expires_at: string | null;
  created_at: string;
  revoked_at: string | null;
  revoked_reason: string | null;
};

export type GrantInput = {
  granteeUserId: string;
  scopePattern?: Record<string, unknown>;
  maxUses?: number;
  expiresAt?: string;
};

export const buildGrantBody = (input: GrantInput): Record<string, unknown> => {
  const body: Record<string, unknown> = { grantee_user_id: input.granteeUserId };
  if (input.scopePattern !== undefined) body.scope_pattern = input.scopePattern;
  if (input.maxUses !== undefined) body.max_uses = input.maxUses;
  if (input.expiresAt !== undefined) body.expires_at = input.expiresAt;
  return body;
};

export const grantSendCap = async (
  input: GrantInput,
  opts: { apiBase: string; token: string; workspaceId: string },
): Promise<{ send_cap: SendCap }> => {
  const url = `${opts.apiBase}/v1/workspaces/${encodeURIComponent(opts.workspaceId)}/send-caps`;
  return requestJson("POST", url, opts.token, buildGrantBody(input));
};

export type ListFilter = {
  issuerUserId?: string;
  granteeUserId?: string;
  active?: boolean;
};

export const listSendCaps = async (
  filter: ListFilter,
  opts: { apiBase: string; token: string; workspaceId: string },
): Promise<{ send_caps: SendCap[] }> => {
  const url = new URL(
    `${opts.apiBase}/v1/workspaces/${encodeURIComponent(opts.workspaceId)}/send-caps`,
  );
  if (filter.issuerUserId) url.searchParams.set("issuer_user_id", filter.issuerUserId);
  if (filter.granteeUserId) url.searchParams.set("grantee_user_id", filter.granteeUserId);
  if (filter.active) url.searchParams.set("active", "true");
  return requestJson("GET", url.toString(), opts.token);
};

export const revokeSendCap = async (
  id: string,
  opts: { apiBase: string; token: string; workspaceId: string; reason?: string },
): Promise<{ send_cap: SendCap }> => {
  const url = `${opts.apiBase}/v1/workspaces/${encodeURIComponent(opts.workspaceId)}/send-caps/${encodeURIComponent(id)}`;
  const body: Record<string, unknown> = {};
  if (opts.reason !== undefined) body.reason = opts.reason;
  return requestJson("DELETE", url, opts.token, body);
};

export const formatSendCapsTable = (rows: SendCap[]): string => {
  if (rows.length === 0) return "no send caps\n";
  const headers = ["ID", "ISSUER", "GRANTEE", "USED", "EXPIRES", "REVOKED"];
  const data = rows.map((r) => [
    r.id,
    r.issuer_user_id,
    r.grantee_user_id,
    `${r.used_count}/${r.max_uses ?? "inf"}`,
    r.expires_at ?? "",
    r.revoked_at ?? "",
  ]);
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...data.map((row) => (row[i] ?? "").length)),
  );
  const fmt = (cells: string[]): string =>
    cells.map((c, i) => c.padEnd(widths[i] ?? c.length)).join("  ");
  const lines = [fmt(headers), fmt(widths.map((w) => "-".repeat(w)))];
  for (const row of data) lines.push(fmt(row));
  return `${lines.join("\n")}\n`;
};

const printSendCapHuman = (out: (s: string) => void, cap: SendCap): void => {
  out(`id            ${cap.id}\n`);
  out(`issuer        ${cap.issuer_user_id}\n`);
  out(`grantee       ${cap.grantee_user_id}\n`);
  out(`used          ${cap.used_count}/${cap.max_uses ?? "inf"}\n`);
  if (cap.expires_at) out(`expires       ${cap.expires_at}\n`);
  if (cap.revoked_at) {
    out(`revoked       ${cap.revoked_at}\n`);
    if (cap.revoked_reason) out(`reason        ${cap.revoked_reason}\n`);
  }
};

const runGrant = async (
  argv: readonly string[],
  io: { out: (s: string) => void; err: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const granteeUserId = requireFlag(parsed, "to");
  const scopeRaw = parsed.flags.get("scope");
  let scopePattern: Record<string, unknown> | undefined;
  if (scopeRaw !== undefined) {
    const parsedScope = JSON.parse(scopeRaw) as unknown;
    if (!isRecord(parsedScope)) {
      throw new Error("--scope must be a JSON object");
    }
    scopePattern = parsedScope;
  }
  const maxUses = optionalInt(parsed, "max-uses");
  const expiresAt = parsed.flags.get("expires");

  const base = apiBase(env);
  const token = adminToken(env);
  const wsId = workspaceId(env);
  const input: GrantInput = { granteeUserId };
  if (scopePattern !== undefined) input.scopePattern = scopePattern;
  if (maxUses !== undefined) input.maxUses = maxUses;
  if (expiresAt !== undefined) input.expiresAt = expiresAt;
  const res = await grantSendCap(input, { apiBase: base, token, workspaceId: wsId });
  printSendCapHuman(io.out, res.send_cap);
};

const runList = async (
  argv: readonly string[],
  io: { out: (s: string) => void; err: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const issuerUserId = parsed.flags.get("from");
  const granteeUserId = parsed.flags.get("to");
  const activeFlag = parsed.booleans.has("active");
  const format = parsed.flags.get("format") ?? "table";
  if (format !== "table" && format !== "json") {
    throw new Error("--format must be 'table' or 'json'");
  }
  const base = apiBase(env);
  const token = adminToken(env);
  const wsId = workspaceId(env);
  const filter: ListFilter = {};
  if (issuerUserId !== undefined) filter.issuerUserId = issuerUserId;
  if (granteeUserId !== undefined) filter.granteeUserId = granteeUserId;
  if (activeFlag) filter.active = true;
  const res = await listSendCaps(filter, { apiBase: base, token, workspaceId: wsId });
  if (format === "json") {
    io.out(`${JSON.stringify(res, null, 2)}\n`);
    return;
  }
  io.out(formatSendCapsTable(res.send_caps));
};

const runRevoke = async (
  argv: readonly string[],
  io: { out: (s: string) => void; err: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const id = parsed.positional[0];
  if (!id) {
    throw new Error("usage: pact send-cap revoke <id> [--reason text]");
  }
  const reason = parsed.flags.get("reason");
  if (reason !== undefined && reason.length > REASON_MAX) {
    throw new Error(`--reason too long (max ${REASON_MAX} chars)`);
  }
  const base = apiBase(env);
  const token = adminToken(env);
  const wsId = workspaceId(env);
  const opts: { apiBase: string; token: string; workspaceId: string; reason?: string } = {
    apiBase: base,
    token,
    workspaceId: wsId,
  };
  if (reason !== undefined) opts.reason = reason;
  const res = await revokeSendCap(id, opts);
  printSendCapHuman(io.out, res.send_cap);
};

export type RunResult = { exitCode: number };

export const runSendCap = async (
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
      case "grant":
        await runGrant(rest, io, env);
        return { exitCode: 0 };
      case "list":
        await runList(rest, io, env);
        return { exitCode: 0 };
      case "revoke":
        await runRevoke(rest, io, env);
        return { exitCode: 0 };
      default:
        io.err(
          [
            "usage: pact send-cap grant --to <grantee_user_id> [--scope <json>] [--max-uses N] [--expires <iso>]",
            "       pact send-cap list [--from <issuer>] [--to <grantee>] [--active] [--format json|table]",
            "       pact send-cap revoke <id> [--reason text]",
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
