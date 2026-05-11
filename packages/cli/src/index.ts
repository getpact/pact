#!/usr/bin/env node
import { createWorkspace, devIssue, googleExchange, refresh } from "./api.js";
import { runAuditVerify } from "./audit-verify.js";
import { loadConfig, saveConfig } from "./config.js";
import { type ClientId, installMcpServer } from "./mcp-install.js";
import { serveStdio } from "./mcp-serve.js";
import {
  buildGoogleAuthorizeUrl,
  captureLoopbackCallback,
  generatePkce,
  newState,
  openBrowser,
} from "./oauth.js";

const env = (key: string, fallback?: string): string => {
  const v = process.env[key] ?? fallback;
  if (!v) throw new Error(`missing ${key}`);
  return v;
};

const endpoint = (): string => process.env.PACT_ENDPOINT ?? "http://localhost:8787";

const audience = (): string => process.env.PACT_AUDIENCE ?? "pact-mcp";

const help = () => {
  process.stdout.write(
    [
      "pact <command>",
      "",
      "commands:",
      "  init             create a workspace and store credentials (dev path)",
      "  login            sign in via Google (browser loopback)",
      "  refresh          rotate access token using stored refresh token",
      "  whoami           print the active user and workspace",
      "  status           show endpoint and credential expiry",
      "  mcp install      register Pact MCP server with an agent client",
      "  mcp serve        run the Pact MCP stdio proxy (used by clients)",
      "  audit verify     verify the workspace audit chain end to end",
      "",
      "env:",
      "  PACT_ENDPOINT       issuer URL (default http://localhost:8787)",
      "  PACT_AUDIENCE       token audience (default pact-mcp)",
      "  PACT_AUDIT_EXPECTED_HEAD external audit checkpoint hash",
      "  PACT_GOOGLE_CLIENT  Google OAuth client id (required for login)",
      "  PACT_WORKSPACE_ID   workspace id (required for login)",
      "",
    ].join("\n"),
  );
};

const init = async () => {
  const slug = env("PACT_SLUG");
  const name = process.env.PACT_NAME ?? slug;
  const adminEmail = env("PACT_ADMIN_EMAIL");
  const adminName = process.env.PACT_ADMIN_NAME;
  const created = await createWorkspace(endpoint(), {
    slug,
    name,
    adminEmail,
    ...(adminName ? { adminName } : {}),
  });
  const issued = await devIssue(endpoint(), {
    workspaceId: created.workspaceId,
    email: adminEmail,
    audience: audience(),
  });
  await saveConfig({
    endpoint: endpoint(),
    workspaceId: created.workspaceId,
    workspaceSlug: slug,
    email: adminEmail,
    accessToken: issued.token,
    accessExpiresAt: issued.exp,
    refreshToken: issued.refreshToken,
    refreshExpiresAt: issued.refreshExpiresAt,
  });
  process.stdout.write(`workspace ${slug} created (${created.workspaceId})\n`);
  process.stdout.write(`signed in as ${adminEmail}\n`);
};

const login = async () => {
  const clientId = env("PACT_GOOGLE_CLIENT");
  const workspaceId = env("PACT_WORKSPACE_ID");

  const { codeVerifier, codeChallenge } = await generatePkce();
  const state = newState();

  const cb = await captureLoopbackCallback();
  const authorizeUrl = buildGoogleAuthorizeUrl({
    clientId,
    redirectUri: cb.redirectUri,
    codeChallenge,
    state,
    prompt: "select_account",
  });

  process.stdout.write(`opening browser for Google sign-in...\n`);
  process.stdout.write(`if it does not open, visit:\n  ${authorizeUrl}\n`);
  openBrowser(authorizeUrl);

  const captured = await cb.awaitCallback();
  if (captured.state !== state) {
    throw new Error("oauth state mismatch");
  }

  const issued = await googleExchange(endpoint(), {
    workspaceId,
    code: captured.code,
    codeVerifier,
    redirectUri: cb.redirectUri,
    audience: audience(),
  });

  const cfg = (await loadConfig()) ?? { endpoint: endpoint() };
  await saveConfig({
    ...cfg,
    endpoint: endpoint(),
    workspaceId,
    accessToken: issued.token,
    accessExpiresAt: issued.exp,
    refreshToken: issued.refreshToken,
    refreshExpiresAt: issued.refreshExpiresAt,
  });
  process.stdout.write(
    `signed in. token expires at ${new Date(issued.exp * 1000).toISOString()}\n`,
  );
};

const refreshCmd = async () => {
  const cfg = await loadConfig();
  if (!cfg?.workspaceId || !cfg.refreshToken) {
    process.stderr.write("no stored credentials. run pact init or pact login first.\n");
    process.exit(1);
  }
  const issued = await refresh(endpoint(), {
    workspaceId: cfg.workspaceId,
    refreshToken: cfg.refreshToken,
    audience: audience(),
  });
  await saveConfig({
    ...cfg,
    accessToken: issued.token,
    accessExpiresAt: issued.exp,
    refreshToken: issued.refreshToken,
    refreshExpiresAt: issued.refreshExpiresAt,
  });
  process.stdout.write(
    `refreshed. token expires at ${new Date(issued.exp * 1000).toISOString()}\n`,
  );
};

const whoami = async () => {
  const cfg = await loadConfig();
  if (!cfg?.email) {
    process.stderr.write("not signed in. run pact init or pact login first.\n");
    process.exit(1);
  }
  process.stdout.write(`${cfg.email}\n`);
  process.stdout.write(`workspace ${cfg.workspaceSlug ?? cfg.workspaceId}\n`);
};

const status = async () => {
  const cfg = await loadConfig();
  process.stdout.write(`endpoint ${cfg?.endpoint ?? endpoint()}\n`);
  if (!cfg) {
    process.stdout.write("not signed in\n");
    return;
  }
  process.stdout.write(`workspace ${cfg.workspaceSlug ?? cfg.workspaceId ?? "(unset)"}\n`);
  process.stdout.write(`user ${cfg.email ?? "(unset)"}\n`);
  if (cfg.accessExpiresAt) {
    process.stdout.write(
      `access token expires at ${new Date(cfg.accessExpiresAt * 1000).toISOString()}\n`,
    );
  }
};

const mcp = async () => {
  const sub = process.argv[3];
  switch (sub) {
    case "serve":
      await serveStdio();
      return;
    case "install": {
      const idx = process.argv.indexOf("--client");
      const client = (idx >= 0 ? process.argv[idx + 1] : "claude-desktop") as ClientId;
      if (!["claude-desktop", "claude-code", "cursor"].includes(client)) {
        process.stderr.write(`unsupported client: ${client}\n`);
        process.exit(1);
      }
      const { path, existed } = await installMcpServer(client);
      process.stdout.write(
        `pact MCP server registered (${client}) ${existed ? "in existing config" : "in new config"}\n  ${path}\n`,
      );
      return;
    }
    default:
      process.stderr.write(
        "usage: pact mcp install [--client claude-desktop|claude-code|cursor]\n",
      );
      process.stderr.write("       pact mcp serve\n");
      process.exit(1);
  }
};

const audit = async () => {
  const sub = process.argv[3];
  if (sub !== "verify") {
    process.stderr.write("usage: pact audit verify\n");
    process.exit(1);
  }
  const cfg = await loadConfig();
  const report = await runAuditVerify(cfg);
  if (report.ok) {
    process.stdout.write(`audit chain ok. ${report.eventsChecked} events. head ${report.head}\n`);
    return;
  }
  process.stderr.write(
    `audit chain BROKEN at index ${report.brokenAt.index}: ${report.brokenAt.reason}\n`,
  );
  process.exit(2);
};

const main = async () => {
  const command = process.argv[2];
  switch (command) {
    case undefined:
    case "--help":
    case "-h":
      help();
      return;
    case "init":
      await init();
      return;
    case "login":
      await login();
      return;
    case "refresh":
      await refreshCmd();
      return;
    case "whoami":
      await whoami();
      return;
    case "status":
      await status();
      return;
    case "mcp":
      await mcp();
      return;
    case "audit":
      await audit();
      return;
    default:
      process.stderr.write(`unknown command: ${command}\n`);
      process.exit(1);
  }
};

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`error: ${msg}\n`);
  process.exit(1);
});
