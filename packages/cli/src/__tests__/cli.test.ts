import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

describe("cli config", () => {
  let tmp: string;
  let originalHome: string | undefined;

  beforeEach(() => {
    originalHome = process.env.HOME;
    tmp = mkdtempSync(join(tmpdir(), "pact-cli-"));
    process.env.HOME = tmp;
    vi.resetModules();
  });

  afterEach(() => {
    if (originalHome) {
      process.env.HOME = originalHome;
    } else {
      delete process.env.HOME;
    }
    rmSync(tmp, { recursive: true, force: true });
  });

  it("returns null when no config exists", async () => {
    const { loadConfig } = await import("../config.js");
    const cfg = await loadConfig();
    expect(cfg).toBeNull();
  });

  it("round-trips config through save and load", async () => {
    const { loadConfig, saveConfig } = await import("../config.js");
    await saveConfig({
      endpoint: "https://issuer.test",
      workspaceId: "ws-1",
      workspaceSlug: "acme",
      email: "alice@example.com",
      accessToken: "tok",
      accessExpiresAt: 1234567890,
      refreshToken: "rt",
      refreshExpiresAt: "2026-05-10T00:00:00Z",
    });
    const cfg = await loadConfig();
    expect(cfg?.workspaceSlug).toBe("acme");
    expect(cfg?.email).toBe("alice@example.com");
    expect(cfg?.accessExpiresAt).toBe(1234567890);
  });

  it("config file is written with restrictive permissions", async () => {
    const { saveConfig } = await import("../config.js");
    await saveConfig({ endpoint: "https://issuer.test" });
    const { statSync } = await import("node:fs");
    const path = join(tmp, ".pact", "credentials");
    const mode = statSync(path).mode & 0o777;
    expect(mode).toBe(0o600);
  });
});
