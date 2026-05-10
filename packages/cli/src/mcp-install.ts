import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir, platform } from "node:os";
import { dirname, join } from "node:path";

export type ClientId = "claude-desktop" | "claude-code" | "cursor";

const claudeDesktopPath = (): string => {
  const home = homedir();
  if (platform() === "darwin") {
    return join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
  }
  if (platform() === "win32") {
    const appData = process.env.APPDATA ?? join(home, "AppData", "Roaming");
    return join(appData, "Claude", "claude_desktop_config.json");
  }
  return join(home, ".config", "Claude", "claude_desktop_config.json");
};

const claudeCodePath = (): string => join(homedir(), ".claude.json");

const cursorPath = (): string => {
  const home = homedir();
  if (platform() === "darwin") {
    return join(
      home,
      "Library",
      "Application Support",
      "Cursor",
      "User",
      "globalStorage",
      "mcp.json",
    );
  }
  return join(home, ".cursor", "mcp.json");
};

export const configPathFor = (client: ClientId): string => {
  switch (client) {
    case "claude-desktop":
      return claudeDesktopPath();
    case "claude-code":
      return claudeCodePath();
    case "cursor":
      return cursorPath();
  }
};

const readJsonSafe = async <T>(path: string): Promise<T | null> => {
  try {
    const raw = await readFile(path, "utf8");
    if (!raw.trim()) return null;
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
};

export type McpServerEntry = {
  command: string;
  args: string[];
};

const buildServerEntry = (): McpServerEntry => ({
  command: "npx",
  args: ["@getpact/cli", "mcp", "serve"],
});

export const installMcpServer = async (
  client: ClientId,
  serverName = "pact",
): Promise<{ path: string; existed: boolean }> => {
  const path = configPathFor(client);
  const existing = await readJsonSafe<Record<string, unknown>>(path);
  const next: Record<string, unknown> = existing ?? {};
  const servers = (next.mcpServers as Record<string, unknown> | undefined) ?? {};
  servers[serverName] = buildServerEntry();
  next.mcpServers = servers;

  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(next, null, 2), { mode: 0o600 });
  return { path, existed: existing !== null };
};
