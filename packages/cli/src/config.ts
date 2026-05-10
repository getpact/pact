import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

export type CliConfig = {
  endpoint: string;
  workspaceId?: string;
  workspaceSlug?: string;
  email?: string;
  accessToken?: string;
  accessExpiresAt?: number;
  refreshToken?: string;
  refreshExpiresAt?: string;
};

const dir = (): string => join(homedir(), ".pact");
const path = (): string => join(dir(), "credentials");

export const loadConfig = async (): Promise<CliConfig | null> => {
  try {
    const raw = await readFile(path(), "utf8");
    return JSON.parse(raw) as CliConfig;
  } catch {
    return null;
  }
};

export const saveConfig = async (cfg: CliConfig): Promise<void> => {
  await mkdir(dir(), { recursive: true, mode: 0o700 });
  await writeFile(path(), JSON.stringify(cfg, null, 2), { mode: 0o600 });
};

export const ensureConfigDir = async (): Promise<void> => {
  try {
    await stat(dir());
  } catch {
    await mkdir(dir(), { recursive: true, mode: 0o700 });
  }
};
