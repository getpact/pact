#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { googleExchange, refresh } from "./api.js";
import { runAuditCheckpoint, runAuditVerify } from "./audit-verify.js";
import { runAdmin } from "./commands/admin.js";
import { runAgent } from "./commands/agent.js";
import { runGroup } from "./commands/group.js";
import { runInitFromArgv } from "./commands/init.js";
import { runInvite } from "./commands/invite.js";
import { runMcpBridge } from "./commands/mcp-bridge.js";
import { runSendCap } from "./commands/send-cap.js";
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
      "  init             create a workspace via Google OAuth (PKCE loopback)",
      "  login            sign in via Google (browser loopback)",
      "  refresh          rotate access token using stored refresh token",
      "  whoami           print the active user and workspace",
      "  status           show endpoint and credential expiry",
      "  mcp install      register Pact MCP server with an agent client",
      "  mcp serve        stdio MCP server for clients that spawn a subprocess (Claude Code stdio)",
      "  mcp bridge       local http MCP bridge that signs a kb-jwt per call (Cursor, Codex, Claude Code http)",
      "  audit verify     verify the workspace audit chain end to end",
      "  audit checkpoint export a signed audit head checkpoint",
      "  agent mint       mint an agent capability token",
      "  agent revoke     revoke an agent capability by jti",
      "  agent list       list agents in a workspace",
      "  send-cap grant   grant a sender consent to address you",
      "  send-cap list    list send caps in a workspace",
      "  send-cap revoke  revoke a send cap by id",
      "  group create     create a group",
      "  group list       list groups",
      "  group add-member add a user to a group",
      "  group remove-member remove a user from a group",
      "  invite           mint a signed invite for an email",
      "  admin prune-replay-log  prune kbjwt_replay_log rows older than a window",
      "  admin backfill   seed missing adapter-drive keys and default audiences",
      "  mek rewrap       rewrap stored secrets with a new MEK",
      "",
      "env:",
      "  PACT_ENDPOINT       issuer URL (default http://localhost:8787)",
      "  PACT_AUDIENCE       token audience (default pact-mcp)",
      "  PACT_AUDIT_EXPECTED_HEAD external audit checkpoint hash",
      "  PACT_AUDIT_CHECKPOINT_FILE signed checkpoint path",
      "  PACT_AUDIT_CHECKPOINT_SECRET HMAC key for checkpoints",
      "  PACT_GOOGLE_CLIENT  Google OAuth client id (required for login; honored by init as fallback)",
      "  PACT_GOOGLE_CLIENT_ID Google OAuth client id (preferred for init unless --skip-oauth)",
      "  PACT_WORKSPACE_ID   workspace id (required for login and agent list)",
      "  PACT_API_BASE       issuer base for agent commands (default https://issuer.getpact.dev)",
      "  PACT_ADMIN_TOKEN    admin bearer token for agent commands",
      "  DATABASE_URL        postgres dsn (required for mek rewrap)",
      "  PACT_MEK_OLD        base64 current MEK (required for mek rewrap)",
      "  PACT_MEK_NEW        base64 new MEK (required for mek rewrap)",
      "",
    ].join("\n"),
  );
};

const init = async () => {
  await runInitFromArgv(process.argv.slice(3));
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
    case "bridge": {
      const result = await runMcpBridge(process.argv.slice(4));
      if (result.exitCode !== 0) process.exit(result.exitCode);
      return;
    }
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
      process.stderr.write("       pact mcp serve   (stdio; client spawns this as a subprocess)\n");
      process.stderr.write(
        "       pact mcp bridge --upstream <url> [--port 8765]   (http; client connects over localhost)\n",
      );
      process.exit(1);
  }
};

const audit = async () => {
  const sub = process.argv[3];
  if (sub !== "verify" && sub !== "checkpoint") {
    process.stderr.write("usage: pact audit verify\n");
    process.stderr.write("       pact audit checkpoint\n");
    process.exit(1);
  }
  const cfg = await loadConfig();
  if (sub === "checkpoint") {
    const checkpoint = await runAuditCheckpoint(cfg);
    const json = `${JSON.stringify(checkpoint, null, 2)}\n`;
    const file = process.env.PACT_AUDIT_CHECKPOINT_FILE;
    if (file) {
      writeFileSync(file, json, { mode: 0o600 });
      process.stdout.write(`audit checkpoint written to ${file}\n`);
    } else {
      process.stdout.write(json);
    }
    return;
  }
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

const mek = async () => {
  const sub = process.argv[3];
  if (sub !== "rewrap") {
    process.stderr.write("usage: pact mek rewrap [--apply] [--new-key-id <id>]\n");
    process.exit(1);
  }
  const args = process.argv.slice(4);
  const apply = args.includes("--apply");
  const idIdx = args.indexOf("--new-key-id");
  const newKeyId = idIdx >= 0 ? args[idIdx + 1] : undefined;
  const databaseUrl = env("DATABASE_URL");
  const oldB64 = env("PACT_MEK_OLD");
  const newB64 = env("PACT_MEK_NEW");
  const { fromBase64 } = await import("@getpact/crypto");
  const { rewrapMek } = await import("@getpact/db/rewrap-mek");
  const result = await rewrapMek({
    databaseUrl,
    oldMek: fromBase64(oldB64),
    newMek: fromBase64(newB64),
    ...(newKeyId ? { newMekKeyId: newKeyId } : {}),
    apply,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.applied) {
    process.stdout.write("dry run only. pass --apply to persist changes.\n");
  }
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
    case "mek":
      await mek();
      return;
    case "agent": {
      const result = await runAgent(process.argv.slice(3));
      if (result.exitCode !== 0) process.exit(result.exitCode);
      return;
    }
    case "send-cap": {
      const result = await runSendCap(process.argv.slice(3));
      if (result.exitCode !== 0) process.exit(result.exitCode);
      return;
    }
    case "admin": {
      const result = await runAdmin(process.argv.slice(3));
      if (result.exitCode !== 0) process.exit(result.exitCode);
      return;
    }
    case "group": {
      const result = await runGroup(process.argv.slice(3));
      if (result.exitCode !== 0) process.exit(result.exitCode);
      return;
    }
    case "invite": {
      const result = await runInvite(process.argv.slice(3));
      if (result.exitCode !== 0) process.exit(result.exitCode);
      return;
    }
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
