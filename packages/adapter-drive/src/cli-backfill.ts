#!/usr/bin/env node
import { type BrainPutFn, type IngestResult, ingestRecentDriveDocs } from "./ingest.js";

type Args = {
  workspace: string;
  user: string;
  email: string;
  accessToken: string;
  endpoint: string;
  bearer: string;
  since?: string;
  limit?: number;
  retries?: number;
};

const HELP = `pact-drive-backfill - one-shot ingest of recent Drive docs into brain.

Usage:
  pact-drive-backfill --workspace <uuid> --user <uuid> --email <addr> [options]

Required:
  --workspace <uuid>      target workspace
  --user <uuid>           user id whose Drive token is used
  --email <addr>          user email (for AdapterContext)

Auth (any of):
  --access-token <tok>    Drive OAuth access token (or env DRIVE_ACCESS_TOKEN)
  --bearer <jwt>          Pact MCP bearer for brain.put (or env PACT_BEARER)

Brain transport:
  --endpoint <url>        MCP server base URL (or env PACT_MCP_ENDPOINT,
                          default http://localhost:8790)

Options:
  --since <iso>           floor cursor (default now - 30 days)
  --limit <n>             max files to process (default 50)
  --retries <n>           Drive transient retries (default 3)
  --help                  print this help
`;

const parseArgs = (argv: string[]): Args => {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] ?? "";
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(HELP);
      process.exit(0);
    }
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) {
      out[key] = "true";
    } else {
      out[key] = next;
      i += 1;
    }
  }

  const workspace = out.workspace ?? "";
  const user = out.user ?? "";
  const email = out.email ?? "";
  const accessToken = out["access-token"] ?? process.env.DRIVE_ACCESS_TOKEN ?? "";
  const bearer = out.bearer ?? process.env.PACT_BEARER ?? "";
  const endpoint = out.endpoint ?? process.env.PACT_MCP_ENDPOINT ?? "http://localhost:8790";

  const missing: string[] = [];
  if (!workspace) missing.push("--workspace");
  if (!user) missing.push("--user");
  if (!email) missing.push("--email");
  if (!accessToken) missing.push("--access-token or DRIVE_ACCESS_TOKEN");
  if (!bearer) missing.push("--bearer or PACT_BEARER");
  if (missing.length > 0) {
    process.stderr.write(`missing required: ${missing.join(", ")}\n\n${HELP}`);
    process.exit(2);
  }

  const result: Args = {
    workspace,
    user,
    email,
    accessToken,
    bearer,
    endpoint,
  };
  if (out.since) result.since = out.since;
  if (out.limit) result.limit = Number(out.limit);
  if (out.retries) result.retries = Number(out.retries);
  return result;
};

const httpBrainPut = (endpoint: string, bearer: string): BrainPutFn => {
  let nextId = 1;
  const callUrl = `${endpoint.replace(/\/+$/, "")}/mcp`;
  return async (input) => {
    const id = nextId++;
    const response = await fetch(callUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${bearer}`,
        accept: "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id,
        method: "tools/call",
        params: {
          name: "pact.brain.put",
          arguments: input,
        },
      }),
    });
    if (!response.ok) {
      return {
        content: [{ type: "text", text: `brain.put http ${response.status}` }],
        isError: true,
      };
    }
    const body = (await response.json().catch(() => ({}))) as {
      result?: { content?: Array<{ type: string; text: string }>; isError?: boolean };
      error?: { message?: string };
    };
    if (body.error?.message) {
      return {
        content: [{ type: "text", text: body.error.message }],
        isError: true,
      };
    }
    const content = body.result?.content ?? [{ type: "text", text: "" }];
    const normalized = content.map((c) => ({
      type: "text" as const,
      text: typeof c.text === "string" ? c.text : "",
    }));
    return {
      content: normalized,
      ...(body.result?.isError ? { isError: true } : {}),
    };
  };
};

const summarize = (result: IngestResult): string => {
  const lines = [
    `ingested:   ${result.ingested}`,
    `duplicates: ${result.duplicates}`,
    `skipped:    ${result.skipped}`,
    `errors:     ${result.errors.length}`,
    `cursor:     ${result.nextCursor}`,
  ];
  for (const err of result.errors.slice(0, 10)) {
    lines.push(`  ${err.fileId}: ${err.reason}`);
  }
  if (result.errors.length > 10) {
    lines.push(`  ... and ${result.errors.length - 10} more`);
  }
  return lines.join("\n");
};

const main = async (): Promise<void> => {
  const args = parseArgs(process.argv.slice(2));
  const brainPut = httpBrainPut(args.endpoint, args.bearer);
  const ingestOpts: Parameters<typeof ingestRecentDriveDocs>[0] = {
    workspaceId: args.workspace,
    userId: args.user,
    email: args.email,
    accessToken: args.accessToken,
    brainPut,
    databaseUrl: process.env.DATABASE_URL ?? "",
  };
  if (args.since) ingestOpts.since = args.since;
  if (args.limit !== undefined) ingestOpts.limit = args.limit;
  if (args.retries !== undefined) ingestOpts.retries = args.retries;

  const result = await ingestRecentDriveDocs(ingestOpts);
  process.stdout.write(`${summarize(result)}\n`);
  if (result.errors.length > 0) process.exit(1);
};

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`backfill failed: ${message}\n`);
  process.exit(1);
});
