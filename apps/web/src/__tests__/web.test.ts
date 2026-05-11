import { afterEach, describe, expect, it, vi } from "vitest";
import app from "../index.js";

const env = {
  ENVIRONMENT: "test",
  WEB_BASE_URL: "https://app.test",
  ISSUER_BASE_URL: "https://issuer.test",
  ADMIN_API_BASE_URL: "https://admin.test",
  AUDIT_API_BASE_URL: "https://audit.test",
  ADMIN_AUDIENCE: "pact-admin",
  GOOGLE_OAUTH_CLIENT_ID: "google-client",
  GOOGLE_OAUTH_AUTHORIZATION_ENDPOINT: "https://accounts.test/oauth",
  WEB_ISSUER_SERVICE_TOKEN: "test-web-issuer-service-token-12345",
};

const workspaceId = "00000000-0000-4000-8000-000000000001";

const token = [
  btoa(JSON.stringify({ alg: "none" })).replace(/=+$/, ""),
  btoa(
    JSON.stringify({
      org: workspaceId,
      sub: "user-1",
      email: "alice@example.com",
      roles: ["admin"],
      exp: 1_800_000_000,
    }),
  ).replace(/=+$/, ""),
  "sig",
].join(".");

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("web dashboard auth", () => {
  it("starts Google login with PKCE and HttpOnly OAuth cookies", async () => {
    const res = await app.request(
      "/v1/auth/google/start",
      {
        method: "POST",
        headers: { "content-type": "application/json", origin: "https://app.test" },
        body: JSON.stringify({ workspaceId }),
      },
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { location: string };
    const location = body.location;
    expect(location).toContain("https://accounts.test/oauth");
    expect(location).toContain("client_id=google-client");
    expect(location).toContain("code_challenge_method=S256");
    const cookies = res.headers.get("set-cookie") ?? "";
    expect(cookies).toContain("__Host-pact-oauth-state=");
    expect(cookies).toContain("__Host-pact-oauth-verifier=");
    expect(cookies).toContain("__Host-pact-oauth-workspace=");
    expect(cookies).toContain("HttpOnly");
  });

  it("rejects cross-site Google login starts", async () => {
    const res = await app.request(
      "/v1/auth/google/start",
      {
        method: "POST",
        headers: { "content-type": "application/json", origin: "https://evil.test" },
        body: JSON.stringify({ workspaceId }),
      },
      env,
    );
    expect(res.status).toBe(403);
  });

  it("rejects OAuth callback state mismatch", async () => {
    const res = await app.request(
      "/v1/auth/google/callback?code=abc&state=bad",
      {
        headers: {
          cookie:
            "__Host-pact-oauth-state=good;__Host-pact-oauth-verifier=v;__Host-pact-oauth-workspace=w",
        },
      },
      env,
    );
    expect(res.status).toBe(401);
  });

  it("exchanges OAuth code and stores tokens in HttpOnly cookies", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          tokens: {
            "pact-admin": {
              token,
              refreshToken: "admin-refresh-1",
              exp: 1_800_000_000,
            },
            "pact-audit": {
              token,
              refreshToken: "audit-refresh-1",
              exp: 1_800_000_000,
            },
          },
        }),
      ),
    );
    const res = await app.request(
      "/v1/auth/google/callback?code=abc&state=state-1",
      {
        headers: {
          cookie: `__Host-pact-oauth-state=state-1;__Host-pact-oauth-verifier=verifier-1;__Host-pact-oauth-workspace=${workspaceId}`,
        },
      },
      env,
    );
    expect(res.status).toBe(302);
    const cookies = res.headers.get("set-cookie") ?? "";
    expect(cookies).toContain("__Host-pact-admin-access=");
    expect(cookies).toContain("__Host-pact-admin-refresh=");
    expect(cookies).toContain("__Host-pact-audit-access=");
    expect(cookies).toContain("__Host-pact-audit-refresh=");
    expect(cookies).toContain("__Host-pact-workspace=");
    expect(cookies).toContain("HttpOnly");
    expect(cookies).toContain("__Host-pact-csrf=");
    expect(cookies).toContain("SameSite=Strict");
    expect(fetch).toHaveBeenCalledWith(
      "https://issuer.test/v1/oauth/google/session",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "x-pact-web-service-token": "test-web-issuer-service-token-12345",
        }),
        body: expect.stringContaining('"audiences":["pact-admin","pact-audit"]'),
      }),
    );
  });

  it("requires CSRF before clearing a session", async () => {
    const res = await app.request("/v1/session", { method: "DELETE" }, env);
    expect(res.status).toBe(403);
  });

  it("rejects cross-origin CSRF attempts", async () => {
    const res = await app.request(
      "/v1/session",
      {
        method: "DELETE",
        headers: {
          origin: "https://evil.test",
          cookie: "__Host-pact-csrf=csrf-1",
          "x-pact-csrf": "csrf-1",
        },
      },
      env,
    );
    expect(res.status).toBe(403);
  });

  it("requires same-origin CSRF before clearing a session", async () => {
    const res = await app.request(
      "/v1/session",
      {
        method: "DELETE",
        headers: {
          origin: "https://app.test",
          cookie: "__Host-pact-csrf=csrf-1",
          "x-pact-csrf": "csrf-1",
        },
      },
      env,
    );
    expect(res.status).toBe(200);
  });

  it("proxies workspace status without exposing tokens to browser code", async () => {
    const calls: Array<{ url: string; auth: string | null }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const headers = new Headers(init?.headers);
        calls.push({ url, auth: headers.get("authorization") });
        if (url.includes("/users")) return Response.json({ users: [{ id: "u1", email: "a" }] });
        if (url.includes("/brains")) {
          return Response.json({
            brains: [{ id: "b1", kind: "google-drive", status: "active", authScheme: "bearer" }],
          });
        }
        return Response.json({ head: { lastHash: "abc" } });
      }),
    );
    const res = await app.request(
      "/v1/workspace/status",
      {
        headers: {
          cookie: `__Host-pact-admin-access=${token};__Host-pact-audit-access=${token};__Host-pact-workspace=${workspaceId}`,
        },
      },
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { connections: { drive: { status: string } } };
    expect(body.connections.drive.status).toBe("active");
    expect(calls).toHaveLength(3);
    expect(calls.every((call) => call.auth === `Bearer ${token}`)).toBe(true);
  });

  it("reports decoded session summary from HttpOnly token cookie", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ users: [] })),
    );
    const res = await app.request(
      "/v1/session",
      {
        headers: {
          cookie: `__Host-pact-admin-access=${token};__Host-pact-workspace=${workspaceId}`,
        },
      },
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { authenticated: boolean; claims: { email: string } };
    expect(body.authenticated).toBe(true);
    expect(body.claims.email).toBe("alice@example.com");
  });

  it("does not authenticate a decoded token if admin auth rejects it", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ error: "unauthorized" }, { status: 401 })),
    );
    const res = await app.request(
      "/v1/session",
      {
        headers: {
          cookie: `__Host-pact-admin-access=${token};__Host-pact-workspace=${workspaceId}`,
        },
      },
      env,
    );
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ authenticated: false });
  });

  it("fails closed when audit status is unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/users")) return Response.json({ users: [] });
        if (url.includes("/brains")) return Response.json({ brains: [] });
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }),
    );
    const res = await app.request(
      "/v1/workspace/status",
      {
        headers: {
          cookie: `__Host-pact-admin-access=${token};__Host-pact-audit-access=${token};__Host-pact-workspace=${workspaceId}`,
        },
      },
      env,
    );
    expect(res.status).toBe(502);
  });

  it("fails closed when brain status is unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/users")) return Response.json({ users: [] });
        if (url.includes("/brains")) return Response.json({ error: "down" }, { status: 503 });
        return Response.json({ head: { lastHash: "abc" } });
      }),
    );
    const res = await app.request(
      "/v1/workspace/status",
      {
        headers: {
          cookie: `__Host-pact-admin-access=${token};__Host-pact-audit-access=${token};__Host-pact-workspace=${workspaceId}`,
        },
      },
      env,
    );
    expect(res.status).toBe(502);
  });

  it("ignores malformed cookie encoding instead of throwing", async () => {
    const res = await app.request(
      "/v1/session",
      { headers: { cookie: "__Host-pact-admin-access=%;__Host-pact-workspace=%" } },
      env,
    );
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ authenticated: false });
  });
});
