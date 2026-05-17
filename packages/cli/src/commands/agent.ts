import { readFile, writeFile } from "node:fs/promises";
import { generateEd25519Keypair } from "@getpact/crypto";
import { parseDurationToSeconds } from "../duration.js";

const DEFAULT_API_BASE = "https://issuer.getpact.dev";
const TTL_DEFAULT = 300;
const REDEEMS_DEFAULT = 1;
const REASON_MAX = 280;

export type ApiError = {
  status: number;
  code: string;
  message: string;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const apiBase = (env: NodeJS.ProcessEnv = process.env): string =>
  (env.PACT_API_BASE ?? DEFAULT_API_BASE).replace(/\/+$/, "");

const adminToken = (env: NodeJS.ProcessEnv = process.env): string => {
  const t = env.PACT_ADMIN_TOKEN;
  if (!t || t.length === 0) {
    throw new Error("missing PACT_ADMIN_TOKEN");
  }
  return t;
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
  negated: Set<string>;
};

export const parseFlags = (argv: readonly string[]): ParsedFlags => {
  const positional: string[] = [];
  const flags = new Map<string, string>();
  const booleans = new Set<string>();
  const negated = new Set<string>();
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i] ?? "";
    if (a.startsWith("--no-")) {
      negated.add(a.slice(5));
      continue;
    }
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
  return { positional, flags, booleans, negated };
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

export type MintInput = {
  agent: string;
  onBehalfOf: string;
  tool: string;
  scope: Record<string, unknown>;
  audience: string;
  ttlSeconds: number;
  maxRedeems: number;
  cnfJwk?: Record<string, unknown>;
};

export type MintResponse = {
  jti: string;
  sd_jwt: string;
  exp: number;
  cnf_thumbprint?: string;
};

export const buildMintBody = (input: MintInput): Record<string, unknown> => {
  const body: Record<string, unknown> = {
    on_behalf_of: input.onBehalfOf,
    tool_name: input.tool,
    scope: input.scope,
    audience: input.audience,
    ttl_seconds: input.ttlSeconds,
    max_redeems: input.maxRedeems,
  };
  if (input.cnfJwk) body.cnf_jwk = input.cnfJwk;
  return body;
};

export const mintCapability = async (
  input: MintInput,
  opts: { apiBase: string; token: string },
): Promise<MintResponse> => {
  const url = `${opts.apiBase}/v1/agents/${encodeURIComponent(input.agent)}/capabilities`;
  return requestJson<MintResponse>("POST", url, opts.token, buildMintBody(input));
};

export type RevokeResponse = {
  revoked: string[];
  count: number;
};

export const revokeCapability = async (
  jti: string,
  opts: { apiBase: string; token: string; cascade: boolean; reason?: string },
): Promise<RevokeResponse> => {
  const url = `${opts.apiBase}/v1/capabilities/${encodeURIComponent(jti)}`;
  const body: Record<string, unknown> = { cascade: opts.cascade };
  if (opts.reason !== undefined) body.reason = opts.reason;
  return requestJson<RevokeResponse>("DELETE", url, opts.token, body);
};

export type AgentRow = {
  id: string;
  name?: string;
  slug?: string;
  status: string;
  created_at?: string;
};

export type ListResponse = {
  agents: AgentRow[];
};

export const listAgents = async (opts: {
  apiBase: string;
  token: string;
  workspaceId: string;
  status?: string;
}): Promise<ListResponse> => {
  const url = new URL(`${opts.apiBase}/v1/agents`);
  url.searchParams.set("workspace_id", opts.workspaceId);
  if (opts.status) url.searchParams.set("status", opts.status);
  return requestJson<ListResponse>("GET", url.toString(), opts.token);
};

const truncate = (s: string, n: number): string =>
  s.length <= n ? s : `${s.slice(0, n)}...(truncated, ${s.length} chars total)`;

export const formatAgentsTable = (rows: AgentRow[]): string => {
  if (rows.length === 0) return "no agents\n";
  const headers = ["ID", "NAME", "STATUS", "CREATED"];
  const data = rows.map((r) => [r.id, r.name ?? r.slug ?? "", r.status, r.created_at ?? ""]);
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...data.map((row) => (row[i] ?? "").length)),
  );
  const fmt = (cells: string[]): string =>
    cells.map((c, i) => c.padEnd(widths[i] ?? c.length)).join("  ");
  const lines = [fmt(headers), fmt(widths.map((w) => "-".repeat(w)))];
  for (const row of data) lines.push(fmt(row));
  return `${lines.join("\n")}\n`;
};

const printMintHuman = (out: (s: string) => void, res: MintResponse, apiBaseUrl: string): void => {
  const shareUrl = `${apiBaseUrl}/share/${res.jti}`;
  out(`jti          ${res.jti}\n`);
  out(`exp          ${new Date(res.exp * 1000).toISOString()}\n`);
  if (res.cnf_thumbprint) out(`cnf jkt      ${res.cnf_thumbprint}\n`);
  out(`sd-jwt       ${truncate(res.sd_jwt, 96)}\n`);
  out(`share url    ${shareUrl}\n`);
  out("note: install qrcode-terminal to render the share url as a QR code.\n");
};

const runMint = async (
  argv: readonly string[],
  io: { out: (s: string) => void; err: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const agent = requireFlag(parsed, "agent");
  const onBehalfOf = requireFlag(parsed, "on-behalf-of");
  const tool = requireFlag(parsed, "tool");
  const scopeRaw = requireFlag(parsed, "scope");
  const audience = requireFlag(parsed, "audience");
  let scope: Record<string, unknown>;
  try {
    const parsedScope = JSON.parse(scopeRaw) as unknown;
    if (!isRecord(parsedScope)) {
      throw new Error("--scope must be a JSON object");
    }
    scope = parsedScope;
  } catch (e) {
    throw new Error(`--scope must be valid JSON: ${(e as Error).message}`);
  }
  const ttlFlag = parsed.flags.get("ttl");
  const ttlSeconds = ttlFlag !== undefined ? parseDurationToSeconds(ttlFlag) : TTL_DEFAULT;
  const maxRedeems = optionalInt(parsed, "max-redeems") ?? REDEEMS_DEFAULT;
  let cnfJwk: Record<string, unknown> | undefined;
  const cnfFile = parsed.flags.get("cnf-jwk");
  if (cnfFile) {
    const raw = await readFile(cnfFile, "utf8");
    const parsedJwk = JSON.parse(raw) as unknown;
    if (!isRecord(parsedJwk)) {
      throw new Error("cnf-jwk file must contain a JSON object");
    }
    cnfJwk = parsedJwk;
  } else {
    const pair = await generateEd25519Keypair();
    const publicJwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as Record<
      string,
      unknown
    >;
    cnfJwk = {
      kty: publicJwk.kty,
      crv: publicJwk.crv,
      x: publicJwk.x,
    };
    io.err(
      "note: --cnf-jwk not provided; generated an ephemeral holder keypair. " +
        "The private key is discarded after mint, so the resulting token cannot be redeemed. " +
        "Pass --cnf-jwk <file> with the holder public JWK for redeemable tokens.\n",
    );
    const dumpPath = parsed.flags.get("dump-holder-key");
    if (dumpPath) {
      const privatePkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
      const privateB64 = Buffer.from(privatePkcs8).toString("base64");
      await writeFile(
        dumpPath,
        `${JSON.stringify({ publicJwk: cnfJwk, privatePkcs8Base64: privateB64 }, null, 2)}\n`,
        "utf8",
      );
    }
  }

  const base = apiBase(env);
  const token = adminToken(env);
  const input: MintInput = {
    agent,
    onBehalfOf,
    tool,
    scope,
    audience,
    ttlSeconds,
    maxRedeems,
    ...(cnfJwk ? { cnfJwk } : {}),
  };
  const res = await mintCapability(input, { apiBase: base, token });
  printMintHuman(io.out, res, base);
  io.out(`${res.sd_jwt}\n`);
};

const runRevoke = async (
  argv: readonly string[],
  io: { out: (s: string) => void; err: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const jti = parsed.positional[0];
  if (!jti) {
    throw new Error("usage: pact agent revoke <jti> [--no-cascade] [--reason text]");
  }
  const cascade = !parsed.negated.has("cascade");
  const reason = parsed.flags.get("reason");
  if (reason !== undefined && reason.length > REASON_MAX) {
    throw new Error(`--reason too long (max ${REASON_MAX} chars)`);
  }

  const base = apiBase(env);
  const token = adminToken(env);
  const res = await revokeCapability(jti, {
    apiBase: base,
    token,
    cascade,
    ...(reason !== undefined ? { reason } : {}),
  });
  for (const id of res.revoked) io.out(`${id}\n`);
  io.out(`revoked ${res.count} capability${res.count === 1 ? "" : "ies"}\n`);
};

const runList = async (
  argv: readonly string[],
  io: { out: (s: string) => void; err: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const workspaceId = parsed.flags.get("workspace") ?? env.PACT_WORKSPACE_ID;
  if (!workspaceId) {
    throw new Error("missing workspace id (use --workspace or set PACT_WORKSPACE_ID)");
  }
  const status = parsed.flags.get("status");
  const format = parsed.flags.get("format") ?? "table";
  if (format !== "table" && format !== "json") {
    throw new Error("--format must be 'table' or 'json'");
  }

  const base = apiBase(env);
  const token = adminToken(env);
  const res = await listAgents({
    apiBase: base,
    token,
    workspaceId,
    ...(status ? { status } : {}),
  });
  if (format === "json") {
    io.out(`${JSON.stringify(res, null, 2)}\n`);
    return;
  }
  io.out(formatAgentsTable(res.agents));
};

export type RunResult = { exitCode: number };

export const runAgent = async (
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
      case "mint":
        await runMint(rest, io, env);
        return { exitCode: 0 };
      case "revoke":
        await runRevoke(rest, io, env);
        return { exitCode: 0 };
      case "list":
        await runList(rest, io, env);
        return { exitCode: 0 };
      default:
        io.err(
          [
            "usage: pact agent mint --agent <id> --on-behalf-of <user> --tool <name> --scope <json> --audience <aud> [--ttl 7d|1h|300] [--max-redeems n] [--cnf-jwk file] [--dump-holder-key file]",
            "       (if --cnf-jwk is omitted an ephemeral holder keypair is generated; the resulting token is not redeemable unless --dump-holder-key is used)",
            "       pact agent revoke <jti> [--no-cascade] [--reason text]",
            "       pact agent list [--workspace id] [--status active|suspended|revoked] [--format json|table]",
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
