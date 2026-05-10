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
