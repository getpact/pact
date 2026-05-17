const DEFAULT_API_BASE = "https://issuer.getpact.dev";
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 200;

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
  } catch {
    // body is not json; keep defaults
  }
  if (res.status === 401 && code === `http_${res.status}`) {
    code = "unauthorized";
    message = "admin token invalid or expired";
  }
  return { status: res.status, code, message };
};

const getJson = async <T>(url: string, token: string): Promise<T> => {
  const res = await fetch(url, {
    method: "GET",
    headers: {
      authorization: `Bearer ${token}`,
      accept: "application/json",
    },
  });
  if (!res.ok) throw new CliApiError(await parseErrorBody(res));
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

export type AuditEventRow = {
  id: string;
  workspaceId: string;
  auditSeq: number;
  ts: string;
  actorKind: string;
  actorId: string | null;
  action: string;
  target: unknown;
  decision: string;
  supporting: unknown;
  signingKeyId: string;
  prevHash: string;
  thisHash: string;
  signature: string;
};

export type AuditEventsResponse = {
  events: AuditEventRow[];
  nextCursor: string | null;
};

export const fetchAuditEvents = async (opts: {
  apiBase: string;
  token: string;
  workspaceId: string;
  limit: number;
  after?: string;
  action?: string;
}): Promise<AuditEventsResponse> => {
  const url = new URL(
    `${opts.apiBase}/v1/workspaces/${encodeURIComponent(opts.workspaceId)}/audit/events`,
  );
  url.searchParams.set("limit", String(opts.limit));
  url.searchParams.set("order", "desc");
  if (opts.after) url.searchParams.set("cursor", opts.after);
  if (opts.action) url.searchParams.set("action", opts.action);
  return getJson<AuditEventsResponse>(url.toString(), opts.token);
};

const truncate = (s: string, n: number): string => (s.length <= n ? s : `${s.slice(0, n - 3)}...`);

const formatTs = (raw: string): string => {
  const d = new Date(raw);
  if (Number.isNaN(d.valueOf())) return raw;
  return d
    .toISOString()
    .replace("T", " ")
    .replace(/\.\d+Z$/, "Z");
};

export const formatEventsTable = (rows: AuditEventRow[]): string => {
  if (rows.length === 0) return "no audit events\n";
  const headers = ["TS", "ACTOR", "ACTION", "DECISION"];
  const data = rows.map((r) => [
    formatTs(r.ts),
    truncate(r.actorId ?? r.actorKind, 36),
    truncate(r.action, 48),
    r.decision,
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

const optionalInt = (parsed: ParsedFlags, name: string): number | undefined => {
  const v = parsed.flags.get(name);
  if (v === undefined) return undefined;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`flag --${name} must be a positive integer`);
  }
  return n;
};

const runTail = async (
  argv: readonly string[],
  io: { out: (s: string) => void; err: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const workspaceId = parsed.flags.get("workspace") ?? env.PACT_WORKSPACE_ID;
  if (!workspaceId || workspaceId.length === 0) {
    throw new Error("missing workspace id (use --workspace or set PACT_WORKSPACE_ID)");
  }
  const limitFlag = optionalInt(parsed, "limit");
  const limit = Math.min(limitFlag ?? DEFAULT_LIMIT, MAX_LIMIT);
  const after = parsed.flags.get("after");
  const action = parsed.flags.get("action");
  const format = parsed.flags.get("format") ?? "table";
  if (format !== "table" && format !== "json") {
    throw new Error("--format must be 'table' or 'json'");
  }

  const base = apiBase(env);
  const token = adminToken(env);
  const res = await fetchAuditEvents({
    apiBase: base,
    token,
    workspaceId,
    limit,
    ...(after ? { after } : {}),
    ...(action ? { action } : {}),
  });
  if (format === "json") {
    io.out(`${JSON.stringify(res, null, 2)}\n`);
    return;
  }
  io.out(formatEventsTable(res.events));
  if (res.nextCursor) {
    io.out(`next cursor: ${res.nextCursor}\n`);
  }
};

export type RunResult = { exitCode: number };

export const runAuditCmd = async (
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
      case "tail":
        await runTail(rest, io, env);
        return { exitCode: 0 };
      default:
        io.err(
          [
            "usage: pact audit tail [--workspace id] [--limit 100] [--after cursor] [--action name] [--format table|json]",
            "",
            "env:",
            "  PACT_ADMIN_TOKEN     admin bearer token",
            "  PACT_WORKSPACE_ID    workspace id (or use --workspace)",
            "  PACT_ADMIN_API_BASE  admin api base url (default https://issuer.getpact.dev)",
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
