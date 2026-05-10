#!/usr/bin/env node
import { createWorkspace, devIssue, refresh } from "./api.js";
import { loadConfig, saveConfig } from "./config.js";

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
      "  init    create a workspace and store credentials",
      "  login   refresh credentials using stored refresh token",
      "  whoami  print the active user and workspace",
      "  status  show endpoint and credential expiry",
      "",
      "env:",
      "  PACT_ENDPOINT  issuer URL (default http://localhost:8787)",
      "  PACT_AUDIENCE  token audience (default pact-mcp)",
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
  const cfg = await loadConfig();
  if (!cfg || !cfg.workspaceId || !cfg.refreshToken) {
    process.stderr.write("no stored credentials. run pact init first.\n");
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
  if (!cfg || !cfg.email) {
    process.stderr.write("not signed in. run pact init first.\n");
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
    case "whoami":
      await whoami();
      return;
    case "status":
      await status();
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
