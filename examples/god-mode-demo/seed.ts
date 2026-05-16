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

type SeedResult = {
  inserted: number;
  idempotent: number;
  failed: number;
  total: number;
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

// content is derived from the id so re-runs hash to the same value and the
// brain page lookup short-circuits via the idempotent path.
export const contentForFile = (file: DriveFile): string => {
  const folder = file.parents[0] ?? "folder_unknown";
  return [
    `# ${file.name}`,
    "",
    `source folder: ${folder}`,
    `mime type:     ${file.mimeType}`,
    `modified:      ${file.modifiedTime}`,
    `size:          ${file.size} bytes`,
    "",
    `Page body for ${file.id}. This document belongs to ${folder} and was`,
    "ingested as part of the god-mode demo seed. The text is deterministic so",
    "subsequent runs hash to the same content and skip via idempotency.",
  ].join("\n");
};

export type BrainPutCall = {
  source_uri: string;
  source_kind: "manual" | "connector";
  content: string;
  title?: string;
  audience?: string[];
};

export const buildPutCall = (file: DriveFile): BrainPutCall => {
  const folder = file.parents[0] ?? "folder_unknown";
  return {
    source_uri: `gdrive://${file.id}`,
    source_kind: "connector",
    content: contentForFile(file),
    title: file.name,
    audience: [folder],
  };
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

type PutOutcome = "inserted" | "idempotent" | "failed";

const parsePutOutcome = (body: McpResponse): PutOutcome => {
  if (body.error) return "failed";
  if (body.result?.isError) return "failed";
  const text = body.result?.content?.[0]?.text;
  if (!text) return "failed";
  try {
    const parsed = JSON.parse(text) as { idempotent?: boolean };
    return parsed.idempotent ? "idempotent" : "inserted";
  } catch {
    return "failed";
  }
};

export type SeedDeps = {
  mcpUrl: string;
  token: string;
  fetchImpl?: typeof fetch;
};

export const seedFile = async (
  file: DriveFile,
  deps: SeedDeps,
  id: number,
): Promise<PutOutcome> => {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const args = buildPutCall(file);
  const res = await fetchImpl(deps.mcpUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${deps.token}`,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: { name: "pact.brain.put", arguments: args },
    }),
  });
  if (!res.ok) return "failed";
  const body = (await res.json()) as McpResponse;
  return parsePutOutcome(body);
};

export const seedAll = async (fixture: DriveFixture, deps: SeedDeps): Promise<SeedResult> => {
  let inserted = 0;
  let idempotent = 0;
  let failed = 0;
  let id = 1;
  for (const file of fixture.files) {
    const outcome = await seedFile(file, deps, id);
    id += 1;
    if (outcome === "inserted") inserted += 1;
    else if (outcome === "idempotent") idempotent += 1;
    else failed += 1;
  }
  return { inserted, idempotent, failed, total: fixture.files.length };
};

const main = async (): Promise<void> => {
  const mcpUrl = env("PACT_MCP_URL");
  const token = env("PACT_MCP_TOKEN");
  const fixture = loadFixture();
  if (!mcpUrl || !token) {
    const out = {
      path: "seed",
      mode: "dry-run",
      reason: "set PACT_MCP_URL and PACT_MCP_TOKEN to seed against a live stack",
      total: fixture.files.length,
      sample: fixture.files.slice(0, 3).map(buildPutCall),
    };
    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
    return;
  }
  const result = await seedAll(fixture, { mcpUrl, token });
  process.stdout.write(
    `${JSON.stringify({ path: "seed", mode: "live", mcpUrl, ...result }, null, 2)}\n`,
  );
};

const isEntry = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isEntry) {
  await main();
}
