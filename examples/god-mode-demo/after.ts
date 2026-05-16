import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

type DriveFile = {
  id: string;
  name: string;
  mimeType: string;
  parents: string[];
  modifiedTime: string;
  size: string;
};

type DriveFixture = {
  generatedAt: string;
  folders: { id: string; name: string }[];
  files: DriveFile[];
};

type CapabilityScope = {
  folder_id: string[];
};

type MintResponse = {
  jti: string;
  sd_jwt: string;
  exp: number;
  cnf_thumbprint?: string;
};

export type ScopedCapability = {
  jti: string;
  token: string;
  scope: CapabilityScope;
  issuedAt: string;
  expiresAt: string;
  audience: string;
  cnf_thumbprint?: string;
  source: "live" | "stub";
};

type SearchHit = {
  source_uri: string;
  snippet: string;
  score: number;
  page_id: string | null;
  chunk_id: string | null;
};

type SearchOutcome = {
  hits: SearchHit[];
  source: "live" | "fixture";
};

const here = dirname(fileURLToPath(import.meta.url));

const env = (k: string): string | undefined => {
  const v = process.env[k];
  return v && v.length > 0 ? v : undefined;
};

const loadFixture = (): DriveFixture => {
  const raw = readFileSync(join(here, "drive-fixture.json"), "utf8");
  return JSON.parse(raw) as DriveFixture;
};

export type MintArgs = {
  agentId: string;
  onBehalfOf: string;
  tool: string;
  scope: CapabilityScope;
  audience: string;
  ttlSeconds: number;
  maxRedeems: number;
};

export type MintDeps = {
  apiBase: string;
  adminToken: string;
  fetchImpl?: typeof fetch;
};

export const buildMintBody = (input: MintArgs): Record<string, unknown> => ({
  on_behalf_of: input.onBehalfOf,
  tool_name: input.tool,
  scope: input.scope,
  audience: input.audience,
  ttl_seconds: input.ttlSeconds,
  max_redeems: input.maxRedeems,
});

export const mintCapabilityLive = async (
  args: MintArgs,
  deps: MintDeps,
): Promise<ScopedCapability> => {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const url = `${deps.apiBase.replace(/\/+$/, "")}/v1/agents/${encodeURIComponent(args.agentId)}/capabilities`;
  const res = await fetchImpl(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      authorization: `Bearer ${deps.adminToken}`,
    },
    body: JSON.stringify(buildMintBody(args)),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`mint failed: ${res.status} ${detail.slice(0, 200)}`);
  }
  const body = (await res.json()) as MintResponse;
  const issued = new Date();
  return {
    jti: body.jti,
    token: body.sd_jwt,
    scope: args.scope,
    issuedAt: issued.toISOString(),
    expiresAt: new Date(body.exp * 1000).toISOString(),
    audience: args.audience,
    ...(body.cnf_thumbprint ? { cnf_thumbprint: body.cnf_thumbprint } : {}),
    source: "live" as const,
  };
};

export const mintCapabilityStub = async (args: MintArgs): Promise<ScopedCapability> => {
  const now = new Date();
  const expires = new Date(now.getTime() + args.ttlSeconds * 1000);
  const iat = Math.floor(now.getTime() / 1000);
  const exp = Math.floor(expires.getTime() / 1000);
  const jti = `stub-${iat}-${Math.floor(Math.random() * 1e6)
    .toString(16)
    .padStart(6, "0")}`;
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "sd+jwt", kid: "stub" })).toString(
    "base64url",
  );
  const payload = Buffer.from(
    JSON.stringify({
      iss: "stub://pactd",
      sub: `agent_${args.agentId}`,
      aud: args.audience,
      iat,
      exp,
      jti,
      tool_name: args.tool,
      max_redeems: args.maxRedeems,
      on_behalf_of: args.onBehalfOf,
    }),
  ).toString("base64url");
  const signature = "STUB-not-a-real-signature";
  const issuerJws = `${header}.${payload}.${signature}`;
  const disclosurePolicy = Buffer.from(
    JSON.stringify(["stub-salt", "policy", { scope: args.scope }]),
  ).toString("base64url");
  const disclosureAudience = Buffer.from(
    JSON.stringify(["stub-salt", "audience", args.audience]),
  ).toString("base64url");
  const compact = `${issuerJws}~${disclosurePolicy}~${disclosureAudience}~`;
  return {
    jti,
    token: compact,
    scope: args.scope,
    issuedAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    audience: args.audience,
    source: "stub",
  };
};

export const mintCapability = async (args: MintArgs): Promise<ScopedCapability> => {
  const apiBase = env("PACT_API_BASE");
  const adminToken = env("PACT_ADMIN_TOKEN");
  if (apiBase && adminToken) {
    return mintCapabilityLive(args, { apiBase, adminToken });
  }
  return mintCapabilityStub(args);
};

type McpResponse = {
  jsonrpc: "2.0";
  id: number;
  result?: {
    content?: Array<{ type: string; text?: string }>;
    isError?: boolean;
  };
  error?: { code: number; message: string };
};

export type SearchDeps = {
  mcpUrl: string;
  token: string;
  fetchImpl?: typeof fetch;
};

export const searchBrainLive = async (
  query: string,
  k: number,
  deps: SearchDeps,
): Promise<SearchHit[]> => {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const res = await fetchImpl(deps.mcpUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${deps.token}`,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 100,
      method: "tools/call",
      params: { name: "pact.brain.search", arguments: { query, k } },
    }),
  });
  if (!res.ok) {
    throw new Error(`brain.search failed: ${res.status}`);
  }
  const body = (await res.json()) as McpResponse;
  if (body.error) throw new Error(`brain.search error: ${body.error.message}`);
  const text = body.result?.content?.[0]?.text;
  if (!text) throw new Error("brain.search returned no result text");
  const parsed = JSON.parse(text) as {
    results?: Array<{
      source_uri: string;
      snippet?: string;
      score?: number;
      page_id?: string | null;
      chunk_id?: string | null;
    }>;
  };
  return (parsed.results ?? []).map((r) => ({
    source_uri: r.source_uri,
    snippet: r.snippet ?? "",
    score: typeof r.score === "number" ? r.score : 0,
    page_id: r.page_id ?? null,
    chunk_id: r.chunk_id ?? null,
  }));
};

export const fixtureFallbackHits = (
  cap: ScopedCapability,
  fixture: DriveFixture,
  limit: number,
): SearchHit[] => {
  const allowed = new Set(cap.scope.folder_id);
  const matched = fixture.files.filter((file) =>
    file.parents.some((parent) => allowed.has(parent)),
  );
  return matched.slice(0, limit).map((file) => ({
    source_uri: `gdrive://${file.id}`,
    snippet: `${file.name} (${file.mimeType})`,
    score: 0,
    page_id: null,
    chunk_id: null,
  }));
};

export const searchBrain = async (
  cap: ScopedCapability,
  query: string,
  k: number,
  fixture: DriveFixture,
): Promise<SearchOutcome> => {
  const mcpUrl = env("PACT_MCP_URL");
  const token = env("PACT_MCP_TOKEN");
  if (mcpUrl && token) {
    try {
      const hits = await searchBrainLive(query, k, { mcpUrl, token });
      return { hits, source: "live" };
    } catch (e) {
      process.stderr.write(`live brain.search failed: ${(e as Error).message}\n`);
    }
  }
  return { hits: fixtureFallbackHits(cap, fixture, k), source: "fixture" };
};

const sourceUriToFileId = (uri: string): string | null => {
  const prefix = "gdrive://";
  return uri.startsWith(prefix) ? uri.slice(prefix.length) : null;
};

export const applyScopeFilter = (
  hits: SearchHit[],
  cap: ScopedCapability,
  fixture: DriveFixture,
): SearchHit[] => {
  const allowed = new Set(cap.scope.folder_id);
  const byId = new Map(fixture.files.map((f) => [f.id, f]));
  const out: SearchHit[] = [];
  for (const hit of hits) {
    const id = sourceUriToFileId(hit.source_uri);
    if (!id) continue;
    const file = byId.get(id);
    if (!file) continue;
    if (file.parents.some((parent) => allowed.has(parent))) {
      out.push(hit);
    }
  }
  return out;
};

export type AuditEntry = {
  ts: string;
  actor: string;
  action: string;
  decision: string;
  target: Record<string, unknown>;
};

export const buildAuditChain = (cap: ScopedCapability): AuditEntry[] => [
  {
    ts: cap.issuedAt,
    actor: "admin",
    action: "agent.capability.minted",
    decision: "allow",
    target: { jti: cap.jti, audience: cap.audience, scope: cap.scope },
  },
  {
    ts: new Date().toISOString(),
    actor: "agent",
    action: "agent.capability.redeemed",
    decision: "allow",
    target: { jti: cap.jti, audience: cap.audience },
  },
];

export type AfterOutput = {
  path: "after";
  auth: "pact-scoped-sd-jwt";
  scope: CapabilityScope;
  tokenSample: string;
  jti: string;
  expiresAt: string;
  capabilitySource: "live" | "stub";
  searchSource: "live" | "fixture";
  totalFiles: number;
  files: Array<{ source_uri: string; snippet: string; score: number }>;
  audit: AuditEntry[];
  note: string;
};

export const buildOutput = (
  cap: ScopedCapability,
  hits: SearchHit[],
  searchSource: "live" | "fixture",
): AfterOutput => ({
  path: "after",
  auth: "pact-scoped-sd-jwt",
  scope: cap.scope,
  tokenSample: cap.token.slice(0, 24) + "...",
  jti: cap.jti,
  expiresAt: cap.expiresAt,
  capabilitySource: cap.source,
  searchSource,
  totalFiles: hits.length,
  files: hits.map((h) => ({
    source_uri: h.source_uri,
    snippet: h.snippet,
    score: h.score,
  })),
  audit: buildAuditChain(cap),
  note:
    cap.source === "stub" || searchSource === "fixture"
      ? "fallback path active; bring up the local stack (issuer, mcp-server, verifier) and set PACT_API_BASE, PACT_ADMIN_TOKEN, PACT_AGENT_ID, PACT_MCP_URL, PACT_MCP_TOKEN to exercise the live flow"
      : "end-to-end live: capability minted by issuer, brain.search filtered to scope",
});

const SEARCH_QUERY = env("PACT_DEMO_QUERY") ?? "Q3 planning notes";
const SEARCH_K_RAW = env("PACT_DEMO_K");
const SEARCH_K = SEARCH_K_RAW ? Math.max(1, Math.min(50, Number(SEARCH_K_RAW))) : 12;

const main = async (): Promise<void> => {
  const fixture = loadFixture();
  const cap = await mintCapability({
    agentId: env("PACT_AGENT_ID") ?? "00000000-0000-0000-0000-000000000000",
    onBehalfOf: env("PACT_ON_BEHALF_OF") ?? "demo-user@example.com",
    tool: "pact.brain.search",
    scope: { folder_id: ["folder_X"] },
    audience: env("PACT_DEMO_AUDIENCE") ?? "mcp-server.local",
    ttlSeconds: 300,
    maxRedeems: 5,
  });

  const search = await searchBrain(cap, SEARCH_QUERY, SEARCH_K, fixture);
  const scoped = applyScopeFilter(search.hits, cap, fixture);
  const hits = search.source === "fixture" ? search.hits : scoped;
  const output = buildOutput(cap, hits, search.source);

  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
};

const isEntry = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isEntry) {
  await main();
}
