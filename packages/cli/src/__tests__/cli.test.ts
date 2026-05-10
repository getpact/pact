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

describe("oauth helpers", () => {
  it("generatePkce returns base64url verifier and sha256 challenge", async () => {
    const { generatePkce } = await import("../oauth.js");
    const pair = await generatePkce();
    expect(pair.codeVerifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(pair.codeChallenge).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(pair.codeChallenge.length).toBe(43);
  });

  it("newState produces unique values", async () => {
    const { newState } = await import("../oauth.js");
    const a = newState();
    const b = newState();
    expect(a).not.toBe(b);
    expect(a.length).toBeGreaterThan(0);
  });

  it("buildGoogleAuthorizeUrl includes pkce and scopes", async () => {
    const { buildGoogleAuthorizeUrl } = await import("../oauth.js");
    const url = new URL(
      buildGoogleAuthorizeUrl({
        clientId: "abc.apps.googleusercontent.com",
        redirectUri: "http://127.0.0.1:9999/callback",
        codeChallenge: "challenge",
        state: "stateval",
      }),
    );
    expect(url.host).toBe("accounts.google.com");
    expect(url.searchParams.get("client_id")).toBe("abc.apps.googleusercontent.com");
    expect(url.searchParams.get("code_challenge")).toBe("challenge");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("state")).toBe("stateval");
    expect(url.searchParams.get("scope")).toContain("openid");
  });
});

describe("mcp install", () => {
  let tmp: string;
  let originalHome: string | undefined;

  beforeEach(() => {
    originalHome = process.env.HOME;
    tmp = mkdtempSync(join(tmpdir(), "pact-cli-mcp-"));
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

  it("writes pact entry into a fresh claude-code config", async () => {
    const { installMcpServer, configPathFor } = await import("../mcp-install.js");
    const { path, existed } = await installMcpServer("claude-code");
    expect(existed).toBe(false);
    expect(path).toBe(configPathFor("claude-code"));
    const { readFileSync } = await import("node:fs");
    const cfg = JSON.parse(readFileSync(path, "utf8")) as {
      mcpServers: Record<string, { command: string; args: string[] }>;
    };
    expect(cfg.mcpServers.pact?.command).toBe("npx");
    expect(cfg.mcpServers.pact?.args).toContain("@getpact/cli");
    expect(cfg.mcpServers.pact?.args).toContain("mcp");
    expect(cfg.mcpServers.pact?.args).toContain("serve");
  });

  it("merges into existing config without clobbering other servers", async () => {
    const { installMcpServer, configPathFor } = await import("../mcp-install.js");
    const path = configPathFor("claude-code");
    const { mkdirSync, writeFileSync } = await import("node:fs");
    const { dirname } = await import("node:path");
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(
      path,
      JSON.stringify({
        mcpServers: { other: { command: "node", args: ["other.js"] } },
        otherSetting: 42,
      }),
    );

    const { existed } = await installMcpServer("claude-code");
    expect(existed).toBe(true);

    const { readFileSync } = await import("node:fs");
    const cfg = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown> & {
      mcpServers: Record<string, { command: string }>;
    };
    expect(cfg.mcpServers.pact?.command).toBe("npx");
    expect(cfg.mcpServers.other?.command).toBe("node");
    expect(cfg.otherSetting).toBe(42);
  });
});
