import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";
import { type BrainApp, type BrainDocument, buildBrainApp } from "./index.js";

const DEFAULT_PORT = 8899;
const DEFAULT_DOCS: BrainDocument[] = [
  { id: "doc:q4-plan", title: "Q4 plan", snippet: "Targets and milestones for Q4." },
  { id: "doc:onboarding", title: "Onboarding", snippet: "How to get set up on day one." },
  { id: "doc:sec-review", title: "Security review", snippet: "Quarterly threat model notes." },
];

const collectBody = async (req: IncomingMessage): Promise<Buffer> => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer));
  }
  return Buffer.concat(chunks);
};

const honoToNode = (app: BrainApp) => {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (v === undefined) continue;
      if (Array.isArray(v)) {
        for (const item of v) headers.append(k, item);
      } else {
        headers.set(k, v);
      }
    }
    const url = `http://${req.headers.host ?? "localhost"}${req.url ?? "/"}`;
    const init: RequestInit = { method: req.method ?? "GET", headers };
    if (req.method && req.method !== "GET" && req.method !== "HEAD") {
      const body = await collectBody(req);
      if (body.length > 0) {
        const copy = new Uint8Array(body.byteLength);
        copy.set(body);
        init.body = copy.buffer as unknown as BodyInit;
      }
    }
    const response = await app.fetch(new Request(url, init));
    res.statusCode = response.status;
    response.headers.forEach((value, key) => {
      res.setHeader(key, value);
    });
    const buf = Buffer.from(await response.arrayBuffer());
    res.end(buf);
  };
};

export type RunServerOptions = {
  port?: number;
  jwksUri: string;
  audience?: string;
  toolName?: string;
  documents?: BrainDocument[];
};

export type RunningServer = {
  server: Server;
  port: number;
  close: () => Promise<void>;
};

export const runServer = (opts: RunServerOptions): Promise<RunningServer> => {
  const app = buildBrainApp({
    jwksUri: opts.jwksUri,
    audience: opts.audience ?? "pact-brain",
    toolName: opts.toolName ?? "brain.query",
    documents: opts.documents ?? DEFAULT_DOCS,
  });
  const handler = honoToNode(app);
  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      handler(req, res).catch((err) => {
        res.statusCode = 500;
        res.end(JSON.stringify({ allow: false, reason: "unknown", detail: String(err) }));
      });
    });
    server.once("error", reject);
    server.listen(opts.port ?? DEFAULT_PORT, () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : (opts.port ?? DEFAULT_PORT);
      resolve({
        server,
        port,
        close: () =>
          new Promise<void>((resolveClose, rejectClose) => {
            server.close((err) => (err ? rejectClose(err) : resolveClose()));
          }),
      });
    });
  });
};

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const jwksUri = process.env.PACT_JWKS_URI;
  if (!jwksUri) {
    process.stderr.write("PACT_JWKS_URI is required\n");
    process.exit(1);
  }
  const port = Number.parseInt(process.env.PORT ?? `${DEFAULT_PORT}`, 10);
  runServer({ port, jwksUri })
    .then((running) => {
      process.stdout.write(`mode-b-brain listening on http://127.0.0.1:${running.port}\n`);
    })
    .catch((err: unknown) => {
      process.stderr.write(`failed to start: ${String(err)}\n`);
      process.exit(1);
    });
}
