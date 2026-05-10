import { refresh } from "./api.js";
import { type CliConfig, loadConfig, saveConfig } from "./config.js";

const ACCESS_REFRESH_BUFFER_SECONDS = 30;

const ensureFreshAccess = async (cfg: CliConfig): Promise<string> => {
  if (!cfg.accessToken || !cfg.accessExpiresAt) {
    throw new Error("no access token; run pact init or pact login");
  }
  const now = Math.floor(Date.now() / 1000);
  if (cfg.accessExpiresAt > now + ACCESS_REFRESH_BUFFER_SECONDS) {
    return cfg.accessToken;
  }
  if (!cfg.refreshToken || !cfg.workspaceId) {
    throw new Error("access token expired; refresh requires workspaceId and refreshToken");
  }
  const audience = process.env.PACT_AUDIENCE ?? "pact-mcp";
  const issued = await refresh(cfg.endpoint, {
    workspaceId: cfg.workspaceId,
    refreshToken: cfg.refreshToken,
    audience,
  });
  await saveConfig({
    ...cfg,
    accessToken: issued.token,
    accessExpiresAt: issued.exp,
    refreshToken: issued.refreshToken,
    refreshExpiresAt: issued.refreshExpiresAt,
  });
  return issued.token;
};

const mcpEndpoint = (cfg: CliConfig): string => {
  const slug = cfg.workspaceSlug ?? cfg.workspaceId;
  if (!slug) throw new Error("workspaceSlug or workspaceId required in config");
  return `${cfg.endpoint.replace(/\/+$/, "")}/${slug}/mcp`;
};

const writeStdout = (json: unknown): void => {
  process.stdout.write(`${JSON.stringify(json)}\n`);
};

const handleLine = async (cfg: CliConfig, line: string): Promise<void> => {
  let req: { id?: string | number | null };
  try {
    req = JSON.parse(line);
  } catch {
    writeStdout({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
    return;
  }
  try {
    const token = await ensureFreshAccess(cfg);
    const res = await fetch(mcpEndpoint(cfg), {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: line,
    });
    const text = await res.text();
    if (!text) {
      writeStdout({
        jsonrpc: "2.0",
        id: req.id ?? null,
        error: { code: -32000, message: `empty response (${res.status})` },
      });
      return;
    }
    process.stdout.write(text.endsWith("\n") ? text : `${text}\n`);
  } catch (err) {
    const message = err instanceof Error ? err.message : "proxy error";
    writeStdout({
      jsonrpc: "2.0",
      id: req.id ?? null,
      error: { code: -32000, message },
    });
  }
};

export const serveStdio = async (): Promise<void> => {
  const cfg = await loadConfig();
  if (!cfg) {
    process.stderr.write("not signed in. run pact init or pact login first.\n");
    process.exit(1);
  }

  process.stdin.setEncoding("utf8");
  let buffer = "";
  let pump: Promise<void> = Promise.resolve();

  const enqueue = (line: string): void => {
    pump = pump
      .then(() => handleLine(cfg, line))
      .catch((err) => {
        const message = err instanceof Error ? err.message : "proxy error";
        process.stderr.write(`pact mcp serve: ${message}\n`);
      });
  };

  process.stdin.on("data", (chunk) => {
    buffer += chunk;
    let nl = buffer.indexOf("\n");
    while (nl !== -1) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (line) enqueue(line);
      nl = buffer.indexOf("\n");
    }
  });

  process.stdin.on("end", () => {
    if (buffer.trim()) enqueue(buffer.trim());
    pump.finally(() => process.exit(0));
  });
};
