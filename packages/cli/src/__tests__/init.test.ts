import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const base64urlNoPad = (buf: Buffer): string =>
  buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

describe("pkce pair (RFC 7636)", () => {
  it("challenge equals base64url(sha256(verifier)) and verifier length is 43", async () => {
    const { generatePkce } = await import("../oauth.js");
    const pair = await generatePkce();
    expect(pair.codeVerifier.length).toBe(43);
    const expected = base64urlNoPad(createHash("sha256").update(pair.codeVerifier).digest());
    expect(pair.codeChallenge).toBe(expected);
  });

  it("verifier and challenge use the b64url unreserved alphabet", async () => {
    const { generatePkce } = await import("../oauth.js");
    const pair = await generatePkce();
    expect(pair.codeVerifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(pair.codeChallenge).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe("exchangeGoogleCodePublic", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("posts no client_secret and returns id_token", async () => {
    let captured: { url: string; body: URLSearchParams } | null = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL, init?: RequestInit) => {
        captured = {
          url: input.toString(),
          body: new URLSearchParams(init?.body as string),
        };
        return Response.json({ id_token: "fake.id.token" });
      }),
    );
    const { exchangeGoogleCodePublic } = await import("../oauth.js");
    const result = await exchangeGoogleCodePublic({
      clientId: "cid.apps.googleusercontent.com",
      code: "auth-code",
      codeVerifier: "verifier",
      redirectUri: "http://127.0.0.1:5555/callback",
    });
    expect(result.idToken).toBe("fake.id.token");
    if (!captured) throw new Error("fetch was not called");
    const seen = captured as { url: string; body: URLSearchParams };
    expect(seen.body.get("client_id")).toBe("cid.apps.googleusercontent.com");
    expect(seen.body.get("grant_type")).toBe("authorization_code");
    expect(seen.body.get("code_verifier")).toBe("verifier");
    expect(seen.body.get("client_secret")).toBeNull();
    expect(seen.url).toBe("https://oauth2.googleapis.com/token");
  });

  it("rejects when google returns no id_token", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({})),
    );
    const { exchangeGoogleCodePublic } = await import("../oauth.js");
    await expect(
      exchangeGoogleCodePublic({
        clientId: "cid",
        code: "c",
        codeVerifier: "v",
        redirectUri: "http://127.0.0.1:1/cb",
      }),
    ).rejects.toThrow(/no id_token/);
  });

  it("surfaces google error body on non-2xx", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("nope", { status: 400 })),
    );
    const { exchangeGoogleCodePublic } = await import("../oauth.js");
    await expect(
      exchangeGoogleCodePublic({
        clientId: "cid",
        code: "c",
        codeVerifier: "v",
        redirectUri: "http://127.0.0.1:1/cb",
      }),
    ).rejects.toThrow(/google token exchange failed \(400\)/);
  });
});

describe("runInit flow", () => {
  let tmp: string;
  let originalHome: string | undefined;

  beforeEach(() => {
    originalHome = process.env.HOME;
    tmp = mkdtempSync(join(tmpdir(), "pact-cli-init-"));
    process.env.HOME = tmp;
    vi.resetModules();
  });

  afterEach(() => {
    if (originalHome) {
      process.env.HOME = originalHome;
    } else {
      delete process.env.HOME;
    }
    vi.unstubAllGlobals();
    rmSync(tmp, { recursive: true, force: true });
  });

  it("forwards google_id_token from fetchIdToken to /v1/workspaces", async () => {
    const seen: { workspaces?: unknown; devIssue?: unknown } = {};
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL, init?: RequestInit) => {
        const url = input.toString();
        const body = init?.body ? JSON.parse(String(init.body)) : null;
        if (url === "https://issuer.test/v1/workspaces") {
          seen.workspaces = body;
          return Response.json(
            {
              workspaceId: "ws-1",
              adminUserId: "user-1",
              jwtKeyId: "jwt-1",
              auditKeyId: "audit-1",
            },
            { status: 201 },
          );
        }
        if (url === "https://issuer.test/v1/dev/issue") {
          seen.devIssue = body;
          return Response.json({
            token: "access-tok",
            jti: "jti-1",
            exp: 1_900_000_000,
            userId: "user-1",
            refreshToken: "refresh-1",
            refreshExpiresAt: "2099-01-01T00:00:00Z",
          });
        }
        return new Response("unexpected", { status: 500 });
      }),
    );
    const { runInit } = await import("../commands/init.js");
    const out: string[] = [];
    const err: string[] = [];
    const result = await runInit(
      {
        endpoint: "https://issuer.test",
        slug: "acme",
        adminEmail: "alice@acme.com",
        audience: "pact-mcp",
        skipOauth: false,
        fetchIdToken: async () => "fake.google.id_token",
      },
      { out: (s) => out.push(s), err: (s) => err.push(s) },
    );
    expect(result.workspaceId).toBe("ws-1");
    expect(result.mcpUrl).toBe("https://issuer.test/ws-1/mcp");
    expect(seen.workspaces).toMatchObject({
      slug: "acme",
      adminEmail: "alice@acme.com",
      google_id_token: "fake.google.id_token",
    });
    const joined = out.join("");
    expect(joined).toContain("workspace acme created (ws-1)");
    expect(joined).toContain("mcp url: https://issuer.test/ws-1/mcp");

    const { readFileSync } = await import("node:fs");
    const cred = JSON.parse(readFileSync(join(tmp, ".pact", "credentials"), "utf8"));
    expect(cred.workspaceId).toBe("ws-1");
    expect(cred.accessToken).toBe("access-tok");
  });

  it("--skip-oauth path omits google_id_token and warns", async () => {
    const seen: { workspaces?: Record<string, unknown> } = {};
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL, init?: RequestInit) => {
        const url = input.toString();
        const body = init?.body ? JSON.parse(String(init.body)) : null;
        if (url === "https://issuer.test/v1/workspaces") {
          seen.workspaces = body;
          return Response.json(
            {
              workspaceId: "ws-2",
              adminUserId: "user-2",
              jwtKeyId: "jwt-2",
              auditKeyId: "audit-2",
            },
            { status: 201 },
          );
        }
        if (url === "https://issuer.test/v1/dev/issue") {
          return Response.json({
            token: "tok",
            jti: "j",
            exp: 1_900_000_000,
            userId: "user-2",
            refreshToken: "rt",
            refreshExpiresAt: "2099-01-01T00:00:00Z",
          });
        }
        return new Response("unexpected", { status: 500 });
      }),
    );
    const { runInit } = await import("../commands/init.js");
    const out: string[] = [];
    const err: string[] = [];
    await runInit(
      {
        endpoint: "https://issuer.test",
        slug: "skip",
        adminEmail: "bob@skip.dev",
        audience: "pact-mcp",
        skipOauth: true,
      },
      { out: (s) => out.push(s), err: (s) => err.push(s) },
    );
    expect(seen.workspaces).toBeDefined();
    expect(seen.workspaces?.google_id_token).toBeUndefined();
    expect(err.join("")).toContain("warning: --skip-oauth");
  });

  it("runInitFromArgv reads --workspace/--email/--endpoint flags", async () => {
    const seen: { workspaces?: Record<string, unknown> } = {};
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL, init?: RequestInit) => {
        const url = input.toString();
        const body = init?.body ? JSON.parse(String(init.body)) : null;
        if (url === "https://flagcfg.test/v1/workspaces") {
          seen.workspaces = body;
          return Response.json(
            {
              workspaceId: "ws-flag",
              adminUserId: "user-flag",
              jwtKeyId: "k",
              auditKeyId: "k",
            },
            { status: 201 },
          );
        }
        if (url === "https://flagcfg.test/v1/dev/issue") {
          return Response.json({
            token: "t",
            jti: "j",
            exp: 1_900_000_000,
            userId: "user-flag",
            refreshToken: "r",
            refreshExpiresAt: "2099-01-01T00:00:00Z",
          });
        }
        return new Response("unexpected", { status: 500 });
      }),
    );
    const { runInitFromArgv } = await import("../commands/init.js");
    const out: string[] = [];
    const err: string[] = [];
    await runInitFromArgv(
      [
        "--endpoint",
        "https://flagcfg.test",
        "--workspace",
        "flagco",
        "--email",
        "owner@flagco.dev",
        "--skip-oauth",
      ],
      { env: {}, io: { out: (s) => out.push(s), err: (s) => err.push(s) } },
    );
    expect(seen.workspaces).toMatchObject({ slug: "flagco", adminEmail: "owner@flagco.dev" });
    expect(seen.workspaces?.google_id_token).toBeUndefined();
  });

  it("errors when google client id is missing and oauth is required", async () => {
    const { runInitFromArgv } = await import("../commands/init.js");
    await expect(
      runInitFromArgv(["--workspace", "x", "--email", "y@z.dev"], { env: {} }),
    ).rejects.toThrow(/google client id/);
  });

  it("runInitFromArgv falls back to PACT_GOOGLE_CLIENT when CLIENT_ID is unset", async () => {
    // Mock the OAuth loopback so resolution can be observed without a browser.
    const seen: { clientId?: string } = {};
    vi.doMock("../oauth.js", async (importOriginal) => {
      const actual = (await importOriginal()) as Record<string, unknown>;
      return {
        ...actual,
        captureLoopbackCallback: async () => ({
          port: 1,
          redirectUri: "http://127.0.0.1:1/callback",
          awaitCallback: async () => ({ code: "c", state: "s" }),
        }),
        openBrowser: () => undefined,
        newState: () => "s",
        generatePkce: async () => ({ codeVerifier: "v", codeChallenge: "ch" }),
        buildGoogleAuthorizeUrl: (params: { clientId: string }) => {
          seen.clientId = params.clientId;
          return "https://accounts.google.com/o/oauth2/v2/auth";
        },
        exchangeGoogleCodePublic: async (params: { clientId: string }) => {
          seen.clientId = params.clientId;
          return { idToken: "fake.id.token" };
        },
      };
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL) => {
        const url = input.toString();
        if (url.endsWith("/v1/workspaces")) {
          return Response.json(
            {
              workspaceId: "ws-c",
              adminUserId: "u-c",
              jwtKeyId: "k",
              auditKeyId: "k",
            },
            { status: 201 },
          );
        }
        if (url.endsWith("/v1/dev/issue")) {
          return Response.json({
            token: "t",
            jti: "j",
            exp: 1_900_000_000,
            userId: "u-c",
            refreshToken: "r",
            refreshExpiresAt: "2099-01-01T00:00:00Z",
          });
        }
        return new Response("unexpected", { status: 500 });
      }),
    );
    const { runInitFromArgv } = await import("../commands/init.js");
    await runInitFromArgv(
      ["--endpoint", "https://compat.test", "--workspace", "compat", "--email", "u@compat.dev"],
      {
        env: { PACT_GOOGLE_CLIENT: "legacy.apps.googleusercontent.com" },
        io: { out: () => {}, err: () => {} },
      },
    );
    expect(seen.clientId).toBe("legacy.apps.googleusercontent.com");
    vi.doUnmock("../oauth.js");
  });

  it("runInitFromArgv prefers PACT_GOOGLE_CLIENT_ID over PACT_GOOGLE_CLIENT", async () => {
    const seen: { clientId?: string } = {};
    vi.doMock("../oauth.js", async (importOriginal) => {
      const actual = (await importOriginal()) as Record<string, unknown>;
      return {
        ...actual,
        captureLoopbackCallback: async () => ({
          port: 1,
          redirectUri: "http://127.0.0.1:1/callback",
          awaitCallback: async () => ({ code: "c", state: "s" }),
        }),
        openBrowser: () => undefined,
        newState: () => "s",
        generatePkce: async () => ({ codeVerifier: "v", codeChallenge: "ch" }),
        buildGoogleAuthorizeUrl: (params: { clientId: string }) => {
          seen.clientId = params.clientId;
          return "https://accounts.google.com/o/oauth2/v2/auth";
        },
        exchangeGoogleCodePublic: async (params: { clientId: string }) => {
          seen.clientId = params.clientId;
          return { idToken: "fake.id.token" };
        },
      };
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL) => {
        const url = input.toString();
        if (url.endsWith("/v1/workspaces")) {
          return Response.json(
            {
              workspaceId: "ws-p",
              adminUserId: "u-p",
              jwtKeyId: "k",
              auditKeyId: "k",
            },
            { status: 201 },
          );
        }
        if (url.endsWith("/v1/dev/issue")) {
          return Response.json({
            token: "t",
            jti: "j",
            exp: 1_900_000_000,
            userId: "u-p",
            refreshToken: "r",
            refreshExpiresAt: "2099-01-01T00:00:00Z",
          });
        }
        return new Response("unexpected", { status: 500 });
      }),
    );
    const { runInitFromArgv } = await import("../commands/init.js");
    await runInitFromArgv(
      ["--endpoint", "https://pref.test", "--workspace", "pref", "--email", "u@pref.dev"],
      {
        env: {
          PACT_GOOGLE_CLIENT_ID: "preferred.apps.googleusercontent.com",
          PACT_GOOGLE_CLIENT: "legacy.apps.googleusercontent.com",
        },
        io: { out: () => {}, err: () => {} },
      },
    );
    expect(seen.clientId).toBe("preferred.apps.googleusercontent.com");
    vi.doUnmock("../oauth.js");
  });
});
