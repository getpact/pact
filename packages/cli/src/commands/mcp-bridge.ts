import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { sdjwt } from "@getpact/crypto";
import {
  type HolderKey,
  holderKeyPath,
  loadHolderKey,
  loadOrCreateHolderKey,
} from "../holder-key.js";

export type BridgeOptions = {
  upstream: string;
  port: number;
  host: string;
  audience?: string;
  sdJwt: string;
  holder: HolderKey;
};

export type BridgeHandle = {
  server: Server;
  port: number;
  host: string;
  close: () => Promise<void>;
};

const JSONRPC_ERROR_CODE = -32000;

const base64UrlNonce = (): string =>
  randomBytes(16).toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");

const decodeJwtPayload = (jwt: string): Record<string, unknown> | null => {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    const body = Buffer.from(
      (parts[1] ?? "").replace(/-/g, "+").replace(/_/g, "/"),
      "base64",
    ).toString("utf8");
    return JSON.parse(body) as Record<string, unknown>;
  } catch {
    return null;
  }
};

const tokenAudience = (sdJwt: string): string | null => {
  const issuer = sdJwt.split("~")[0];
  if (!issuer) return null;
  const payload = decodeJwtPayload(issuer);
  const aud = payload?.aud;
  return typeof aud === "string" ? aud : null;
};

const readBody = (req: IncomingMessage): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });

const writeJsonRpcError = (
  res: ServerResponse,
  status: number,
  id: unknown,
  message: string,
): void => {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: id ?? null,
    error: { code: JSONRPC_ERROR_CODE, message },
  });
  res.writeHead(status, { "content-type": "application/json" });
  res.end(body);
};

const upstreamErrorReason = (status: number): string => {
  if (status === 401) return "upstream rejected: unauthorized";
  if (status === 403) return "upstream rejected: forbidden";
  if (status === 410) return "upstream rejected: token expired or revoked";
  return `upstream returned ${status}`;
};

const presentToken = async (opts: {
  sdJwt: string;
  holder: HolderKey;
  audience: string;
}): Promise<string> => {
  return sdjwt.signKbJwt({
    holderPrivateKey: opts.holder.privateKey,
    sdJwt: opts.sdJwt,
    audience: opts.audience,
    nonce: base64UrlNonce(),
  });
};

export const handleBridgeRequest = async (
  opts: BridgeOptions,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  if (req.method !== "POST") {
    res.writeHead(405, { "content-type": "text/plain" });
    res.end("method not allowed");
    return;
  }

  const url = new URL(req.url ?? "/", `http://${opts.host}`);
  if (url.pathname !== "/mcp") {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
    return;
  }

  const body = await readBody(req);
  let parsedBody: { id?: unknown } = {};
  try {
    parsedBody = JSON.parse(body.toString("utf8")) as { id?: unknown };
  } catch {
    // bridge still forwards bytes; id stays unknown for error reporting
  }

  const audience = opts.audience ?? tokenAudience(opts.sdJwt);
  if (!audience) {
    writeJsonRpcError(
      res,
      500,
      parsedBody.id,
      "bridge cannot determine audience; pass --audience or use an sd-jwt with aud",
    );
    return;
  }

  let presented: string;
  try {
    presented = await presentToken({
      sdJwt: opts.sdJwt,
      holder: opts.holder,
      audience,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "kb-jwt sign failed";
    writeJsonRpcError(res, 500, parsedBody.id, `kb-jwt sign failed: ${message}`);
    return;
  }

  let upstreamRes: Response;
  try {
    upstreamRes = await fetch(opts.upstream, {
      method: "POST",
      headers: {
        authorization: `Bearer ${presented}`,
        "content-type": req.headers["content-type"] ?? "application/json",
      },
      body: new Uint8Array(body),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "upstream fetch failed";
    writeJsonRpcError(res, 502, parsedBody.id, `upstream unreachable: ${message}`);
    return;
  }

  const buf = Buffer.from(await upstreamRes.arrayBuffer());
  if (upstreamRes.status === 401 || upstreamRes.status === 403 || upstreamRes.status === 410) {
    writeJsonRpcError(
      res,
      upstreamRes.status,
      parsedBody.id,
      upstreamErrorReason(upstreamRes.status),
    );
    return;
  }

  res.writeHead(upstreamRes.status, {
    "content-type": upstreamRes.headers.get("content-type") ?? "application/json",
  });
  res.end(buf);
};

export const startBridge = async (opts: BridgeOptions): Promise<BridgeHandle> => {
  const server = createServer((req, res) => {
    handleBridgeRequest(opts, req, res).catch((err: unknown) => {
      const message = err instanceof Error ? err.message : "bridge error";
      try {
        writeJsonRpcError(res, 500, null, `bridge error: ${message}`);
      } catch {
        try {
          res.end();
        } catch {
          // socket already torn down
        }
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port, opts.host, () => {
      server.off("error", reject);
      resolve();
    });
  });

  const addr = server.address() as AddressInfo;

  const close = (): Promise<void> =>
    new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));

  return { server, port: addr.port, host: opts.host, close };
};

type ParsedArgs = {
  flags: Map<string, string>;
  booleans: Set<string>;
};

const parseArgs = (argv: readonly string[]): ParsedArgs => {
  const flags = new Map<string, string>();
  const booleans = new Set<string>();
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i] ?? "";
    if (!a.startsWith("--")) continue;
    const name = a.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags.set(name, next);
      i += 1;
    } else {
      booleans.add(name);
    }
  }
  return { flags, booleans };
};

const DEFAULT_PORT = 8765;
const DEFAULT_HOST = "127.0.0.1";

export type RunResult = { exitCode: number };

export const runMcpBridge = async (
  argv: readonly string[],
  io: { out: (s: string) => void; err: (s: string) => void } = {
    out: (s) => process.stdout.write(s),
    err: (s) => process.stderr.write(s),
  },
  env: NodeJS.ProcessEnv = process.env,
): Promise<RunResult> => {
  const parsed = parseArgs(argv);

  const upstream = parsed.flags.get("upstream") ?? env.PACT_MCP_UPSTREAM;
  if (!upstream) {
    io.err(
      "usage: pact mcp bridge --upstream <url> [--port 8765] [--host 127.0.0.1] [--audience pact-mcp]\n",
    );
    io.err("env: PACT_SD_JWT (capability token), PACT_MCP_UPSTREAM (alternate to --upstream)\n");
    return { exitCode: 1 };
  }

  const portRaw = parsed.flags.get("port") ?? env.PACT_MCP_PORT;
  const port = portRaw ? Number.parseInt(portRaw, 10) : DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    io.err(`error: invalid port ${portRaw}\n`);
    return { exitCode: 1 };
  }

  const host = parsed.flags.get("host") ?? env.PACT_MCP_HOST ?? DEFAULT_HOST;
  if (host !== DEFAULT_HOST && host !== "localhost") {
    io.err(
      `warning: bridge listening on ${host}; the holder key signs every forwarded call. ` +
        "Restrict access to trusted networks.\n",
    );
  }

  const sdJwt = env.PACT_SD_JWT;
  if (!sdJwt) {
    io.err("error: missing PACT_SD_JWT env var (capability token in sd-jwt compact form)\n");
    return { exitCode: 1 };
  }
  if (!sdJwt.includes("~")) {
    io.err("error: PACT_SD_JWT does not look like an sd-jwt compact form\n");
    return { exitCode: 1 };
  }

  const audience = parsed.flags.get("audience") ?? env.PACT_AUDIENCE;

  const preexisting = await loadHolderKey();
  const holder = preexisting ?? (await loadOrCreateHolderKey());
  if (!preexisting) {
    io.out(`generated new holder key at ${holderKeyPath()} (chmod 0600)\n`);
  }

  const handle = await startBridge({
    upstream,
    port,
    host,
    sdJwt,
    holder,
    ...(audience ? { audience } : {}),
  });

  io.out(`pact mcp bridge listening on http://${handle.host}:${handle.port}/mcp\n`);
  io.out(`forwarding to ${upstream}\n`);
  io.out(`holder jwk thumbprint x=${holder.publicJwk.x.slice(0, 12)}...\n`);

  const shutdown = (): void => {
    handle.close().finally(() => process.exit(0));
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);

  await new Promise<void>(() => {
    // run forever; SIGINT/SIGTERM resolves via process.exit
  });

  return { exitCode: 0 };
};
