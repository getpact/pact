import { exportJWK, generateKeyPair, type KeyLike, SignJWT } from "jose";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import app from "../index.js";

const env = {
  ENVIRONMENT: "test",
  WEB_BASE_URL: "https://app.test",
  ISSUER_BASE_URL: "https://issuer.test",
  ADMIN_API_BASE_URL: "https://admin.test",
  AUDIT_API_BASE_URL: "https://audit.test",
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

let signedToken = "";
let signedAuditToken = "";
let signedOtherUserAuditToken = "";
let jwksBody: { keys: unknown[] };
let signingPrivateKey: KeyLike;

const requestUrl = (input: RequestInfo | URL): string =>
  input instanceof Request ? input.url : String(input);

const setCookieFor = (header: string, name: string): string => {
  const entry = header.split(/,\s*(?=__)/).find((value) => value.startsWith(`${name}=`));
  if (!entry) throw new Error(`missing Set-Cookie entry for ${name}`);
  return entry;
};

beforeAll(async () => {
  const pair = await generateKeyPair("EdDSA", { extractable: true });
  signingPrivateKey = pair.privateKey;
  const jwk = await exportJWK(pair.publicKey);
  jwk.kid = "web-test-key";
  jwk.alg = "EdDSA";
  jwk.use = "sig";
  const now = Math.floor(Date.now() / 1000);
  signedToken = await new SignJWT({
    org: workspaceId,
    sub: "user-1",
    email: "alice@example.com",
    roles: ["admin"],
    groups: [],
  })
    .setProtectedHeader({ alg: "EdDSA", kid: "web-test-key" })
    .setIssuer(env.ISSUER_BASE_URL)
    .setAudience("pact-admin")
    .setJti("web-session-jti")
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(pair.privateKey);
  signedAuditToken = await new SignJWT({
    org: workspaceId,
    sub: "user-1",
    email: "alice@example.com",
    roles: ["auditor"],
    groups: [],
  })
    .setProtectedHeader({ alg: "EdDSA", kid: "web-test-key" })
    .setIssuer(env.ISSUER_BASE_URL)
    .setAudience("pact-audit")
    .setJti("web-audit-session-jti")
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(pair.privateKey);
  signedOtherUserAuditToken = await new SignJWT({
    org: workspaceId,
    sub: "user-2",
    email: "bob@example.com",
    roles: ["auditor"],
    groups: [],
  })
    .setProtectedHeader({ alg: "EdDSA", kid: "web-test-key" })
    .setIssuer(env.ISSUER_BASE_URL)
    .setAudience("pact-audit")
    .setJti("web-audit-other-user-session-jti")
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(pair.privateKey);
  jwksBody = { keys: [jwk] };
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("web dashboard auth", () => {
  it("exposes non-secret runtime config for local OAuth hints", async () => {
    const res = await app.request("/v1/config", {}, env);
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      mode: "nonproduction",
      defaultWorkspaceId: null,
      oauthConfigured: true,
    });
  });

  it("exposes a validated default workspace for demo login", async () => {
    const res = await app.request(
      "/v1/config",
      {},
      { ...env, WEB_DEFAULT_WORKSPACE_ID: workspaceId },
    );
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      defaultWorkspaceId: workspaceId,
    });
  });

  it("does not report OAuth configured when the issuer service token is missing", async () => {
    const res = await app.request(
      "/v1/config",
      {},
      { ...env, WEB_ISSUER_SERVICE_TOKEN: undefined },
    );
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      oauthConfigured: false,
    });
  });

  it("does not expose malformed default workspace config", async () => {
    const res = await app.request(
      "/v1/config",
      {},
      { ...env, WEB_DEFAULT_WORKSPACE_ID: "not-a-workspace" },
    );
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      defaultWorkspaceId: null,
    });
  });

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

  it("supports a configured Google callback path for local OAuth clients", async () => {
    const res = await app.request(
      "/v1/auth/google/start",
      {
        method: "POST",
        headers: { "content-type": "application/json", origin: "http://127.0.0.1:19147" },
        body: JSON.stringify({ workspaceId }),
      },
      {
        ...env,
        ENVIRONMENT: "development",
        WEB_BASE_URL: "http://127.0.0.1:19147",
        WEB_OAUTH_CALLBACK_PATH: "/oauth/oidc/callback",
      },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { location: string };
    expect(new URL(body.location).searchParams.get("redirect_uri")).toBe(
      "http://127.0.0.1:19147/oauth/oidc/callback",
    );
  });

  it("starts Google Drive OAuth with session CSRF and readonly scope", async () => {
    const res = await app.request(
      "/v1/connections/google-drive/start",
      {
        method: "POST",
        headers: {
          origin: "https://app.test",
          "x-pact-csrf": "csrf-1",
          cookie: `__Host-pact-admin-access=${token};__Host-pact-workspace=${workspaceId};__Host-pact-csrf=csrf-1`,
        },
      },
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { location: string };
    const location = new URL(body.location);
    expect(location.searchParams.get("scope")).toContain(
      "https://www.googleapis.com/auth/drive.readonly",
    );
    expect(location.searchParams.get("nonce")).toBeTruthy();
    expect(location.searchParams.get("redirect_uri")).toBe(
      "https://app.test/v1/connections/google-drive/callback",
    );
    const cookies = res.headers.get("set-cookie") ?? "";
    expect(cookies).toContain("__Host-pact-drive-state=");
    expect(cookies).toContain("__Host-pact-drive-verifier=");
    expect(cookies).toContain("__Host-pact-drive-nonce=");
    const bridgeCookie = setCookieFor(cookies, "__Secure-pact-drive-admin-access");
    expect(bridgeCookie).toContain("Path=/v1/connections/google-drive/callback");
    expect(bridgeCookie).toContain("SameSite=Lax");
    expect(bridgeCookie).toContain("Max-Age=600");
    expect(bridgeCookie).toContain("HttpOnly");
    expect(bridgeCookie).toContain("Secure");
    expect(cookies).toContain("__Host-pact-oauth-state=");
    expect(cookies).toContain("Max-Age=0");
    expect(cookies).toContain("HttpOnly");
  });

  it("uses a short-lived Drive callback bridge when strict session cookies are not sent", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(requestUrl(input)).toBe(
        `https://admin.test/v1/workspaces/${workspaceId}/connections/google-drive/oauth`,
      );
      expect(init?.method).toBe("POST");
      expect((init?.headers as Record<string, string>).authorization).toBe("Bearer bridge-token");
      const body = JSON.parse(String(init?.body)) as {
        code: string;
        codeVerifier: string;
        nonce: string;
        redirectUri: string;
      };
      expect(body).toMatchObject({
        code: "drive-code",
        codeVerifier: "verifier-1",
        nonce: "nonce-1",
        redirectUri: "https://app.test/v1/connections/google-drive/callback",
      });
      return Response.json({ connection: { status: "connected" } });
    });
    vi.stubGlobal("fetch", fetchMock);

    const res = await app.request(
      "/v1/connections/google-drive/callback?code=drive-code&state=state-1",
      {
        headers: {
          cookie: [
            "__Host-pact-drive-state=state-1",
            "__Host-pact-drive-verifier=verifier-1",
            `__Host-pact-drive-workspace=${workspaceId}`,
            "__Host-pact-drive-nonce=nonce-1",
            "__Secure-pact-drive-admin-access=bridge-token",
          ].join(";"),
        },
      },
      env,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/");
    const cookies = res.headers.get("set-cookie") ?? "";
    const bridgeClear = setCookieFor(cookies, "__Secure-pact-drive-admin-access");
    expect(bridgeClear).toContain("Max-Age=0");
    expect(bridgeClear).toContain("Path=/v1/connections/google-drive/callback");
  });

  it("routes shared local callback by Drive state even when stale login cookies exist", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ connection: { status: "connected" } })),
    );
    const res = await app.request(
      "http://127.0.0.1:19147/oauth/oidc/callback?code=drive-code&state=drive-state",
      {
        headers: {
          cookie: [
            "__Host-pact-oauth-state=stale-login-state",
            "__Host-pact-oauth-verifier=stale-login-verifier",
            `__Host-pact-oauth-workspace=${workspaceId}`,
            "__Host-pact-drive-state=drive-state",
            "__Host-pact-drive-verifier=drive-verifier",
            `__Host-pact-drive-workspace=${workspaceId}`,
            "__Host-pact-drive-nonce=drive-nonce",
            "__Secure-pact-drive-admin-access=bridge-token",
          ].join(";"),
        },
      },
      {
        ...env,
        ENVIRONMENT: "development",
        WEB_BASE_URL: "http://127.0.0.1:19147",
        WEB_DRIVE_OAUTH_CALLBACK_PATH: "/oauth/oidc/callback",
      },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/");
  });

  it("does not route shared local callback to Drive when state does not match Drive state", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ tokens: {} })),
    );
    const res = await app.request(
      "http://127.0.0.1:19147/oauth/oidc/callback?code=login-code&state=login-state",
      {
        headers: {
          cookie: [
            "__Host-pact-oauth-state=login-state",
            "__Host-pact-oauth-verifier=login-verifier",
            `__Host-pact-oauth-workspace=${workspaceId}`,
            "__Host-pact-drive-state=drive-state",
            "__Host-pact-drive-verifier=drive-verifier",
            `__Host-pact-drive-workspace=${workspaceId}`,
            "__Host-pact-drive-nonce=drive-nonce",
            "__Secure-pact-drive-admin-access=bridge-token",
          ].join(";"),
        },
      },
      {
        ...env,
        ENVIRONMENT: "development",
        WEB_BASE_URL: "http://127.0.0.1:19147",
        WEB_OAUTH_CALLBACK_PATH: "/oauth/oidc/callback",
        WEB_DRIVE_OAUTH_CALLBACK_PATH: "/oauth/oidc/callback",
      },
    );
    expect(res.status).toBe(502);
    const fetchMock = vi.mocked(fetch);
    const firstInput = fetchMock.mock.calls[0]?.[0];
    expect(firstInput).toBeTruthy();
    expect(requestUrl(firstInput as RequestInfo | URL)).toBe(
      "https://issuer.test/v1/oauth/google/session",
    );
  });

  it("rejects Drive callback when neither strict session nor bridge token is sent", async () => {
    const res = await app.request(
      "/v1/connections/google-drive/callback?code=drive-code&state=state-1",
      {
        headers: {
          cookie: [
            "__Host-pact-drive-state=state-1",
            "__Host-pact-drive-verifier=verifier-1",
            `__Host-pact-drive-workspace=${workspaceId}`,
            "__Host-pact-drive-nonce=nonce-1",
          ].join(";"),
        },
      },
      env,
    );
    expect(res.status).toBe(401);
  });

  it("supports sharing the local login callback path for Drive OAuth", async () => {
    const res = await app.request(
      "http://127.0.0.1:19147/v1/connections/google-drive/start",
      {
        method: "POST",
        headers: {
          origin: "http://127.0.0.1:19147",
          "x-pact-csrf": "csrf-1",
          cookie: `__Host-pact-admin-access=${token};__Host-pact-workspace=${workspaceId};__Host-pact-csrf=csrf-1`,
        },
      },
      {
        ...env,
        ENVIRONMENT: "development",
        WEB_BASE_URL: "http://127.0.0.1:19147",
        WEB_DRIVE_OAUTH_CALLBACK_PATH: "/oauth/oidc/callback",
      },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { location: string };
    expect(new URL(body.location).searchParams.get("redirect_uri")).toBe(
      "http://127.0.0.1:19147/oauth/oidc/callback",
    );
  });

  it("accepts localhost origin aliases in local development", async () => {
    const res = await app.request(
      "http://localhost:19147/v1/auth/google/start",
      {
        method: "POST",
        headers: { "content-type": "application/json", origin: "http://localhost:19147" },
        body: JSON.stringify({ workspaceId }),
      },
      { ...env, ENVIRONMENT: "development", WEB_BASE_URL: "http://127.0.0.1:19147" },
    );
    expect(res.status).toBe(200);
  });

  it("does not bypass origin checks for non-loopback development requests", async () => {
    const res = await app.request(
      "https://preview.example/v1/auth/google/start",
      {
        method: "POST",
        headers: { "content-type": "application/json", origin: "https://evil.test" },
        body: JSON.stringify({ workspaceId }),
      },
      { ...env, ENVIRONMENT: "development", WEB_BASE_URL: "http://127.0.0.1:19147" },
    );
    expect(res.status).toBe(403);
  });

  it("accepts loopback local development requests without origin headers", async () => {
    const res = await app.request(
      "http://127.0.0.1:19147/v1/auth/google/start",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ workspaceId }),
      },
      { ...env, ENVIRONMENT: "development", WEB_BASE_URL: "http://127.0.0.1:19147" },
    );
    expect(res.status).toBe(200);
  });

  it("accepts null-origin loopback local development requests", async () => {
    const res = await app.request(
      "http://127.0.0.1:19147/v1/auth/google/start",
      {
        method: "POST",
        headers: { "content-type": "application/json", origin: "null" },
        body: JSON.stringify({ workspaceId }),
      },
      { ...env, ENVIRONMENT: "development", WEB_BASE_URL: "http://127.0.0.1:19147" },
    );
    expect(res.status).toBe(200);
  });

  it("accepts explicit dashboard local-dev requests in development", async () => {
    const res = await app.request(
      "http://127.0.0.1:19147/v1/auth/google/start",
      {
        method: "POST",
        headers: { "content-type": "application/json", "x-pact-local-dev": "1" },
        body: JSON.stringify({ workspaceId }),
      },
      { ...env, ENVIRONMENT: "development", WEB_BASE_URL: "http://127.0.0.1:19147" },
    );
    expect(res.status).toBe(200);
  });

  it("accepts an explicit local Wrangler route origin in development", async () => {
    const res = await app.request(
      "http://app.getpact.dev/v1/auth/google/start",
      {
        method: "POST",
        headers: { "content-type": "application/json", origin: "http://app.getpact.dev" },
        body: JSON.stringify({ workspaceId }),
      },
      {
        ...env,
        ENVIRONMENT: "development",
        WEB_BASE_URL: "http://127.0.0.1:19147",
        WEB_DEV_ROUTE_ORIGIN: "http://app.getpact.dev",
      },
    );
    expect(res.status).toBe(200);
  });

  it("rejects explicit local-dev origin bypass on non-loopback requests", async () => {
    const res = await app.request(
      "https://preview.example/v1/auth/google/start",
      {
        method: "POST",
        headers: { "content-type": "application/json", "x-pact-local-dev": "1" },
        body: JSON.stringify({ workspaceId }),
      },
      { ...env, ENVIRONMENT: "development", WEB_BASE_URL: "http://127.0.0.1:19147" },
    );
    expect(res.status).toBe(403);
  });

  it("ignores explicit local-dev origin bypass in production", async () => {
    const res = await app.request(
      "https://app.test/v1/auth/google/start",
      {
        method: "POST",
        headers: { "content-type": "application/json", "x-pact-local-dev": "1" },
        body: JSON.stringify({ workspaceId }),
      },
      { ...env, ENVIRONMENT: "production" },
    );
    expect(res.status).toBe(403);
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

  it("serves the local OAuth callback alias", async () => {
    const res = await app.request(
      "/oauth/oidc/callback?code=abc&state=bad",
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

  it("renders login failure instead of 500 when issuer exchange throws", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("remote issuer failed");
      }),
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
    expect(res.status).toBe(502);
    expect(await res.text()).toContain("Login failed");
  });

  it("escapes issuer login failure messages", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({ error: "bad", message: "<script>alert(1)</script>" }, { status: 400 }),
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
    const html = await res.text();
    expect(res.status).toBe(400);
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("renders status-specific fallback for non-JSON issuer login failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("worker unavailable", { status: 503 })),
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
    const html = await res.text();
    expect(res.status).toBe(503);
    expect(html).toContain("The issuer is misconfigured or unavailable.");
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
    const bridgeClear = setCookieFor(
      res.headers.get("set-cookie") ?? "",
      "__Secure-pact-drive-admin-access",
    );
    expect(bridgeClear).toContain("Max-Age=0");
    expect(bridgeClear).toContain("Path=/v1/connections/google-drive/callback");
  });

  it("disconnects Drive through the dashboard BFF without exposing tokens", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(requestUrl(input)).toBe(
        "https://admin.test/v1/workspaces/00000000-0000-4000-8000-000000000001/connections/google-drive",
      );
      expect(init?.method).toBe("DELETE");
      expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${token}`);
      return Response.json({ ok: true });
    });
    vi.stubGlobal("fetch", fetchMock);
    const res = await app.request(
      "/v1/connections/google-drive",
      {
        method: "DELETE",
        headers: {
          origin: "https://app.test",
          "x-pact-csrf": "csrf-1",
          cookie: `__Host-pact-admin-access=${token};__Host-pact-workspace=${workspaceId};__Host-pact-csrf=csrf-1`,
        },
      },
      env,
    );
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ ok: true });
  });

  it("proxies workspace status without exposing tokens to browser code", async () => {
    const calls: Array<{ url: string; auth: string | null }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        const headers = new Headers(init?.headers);
        calls.push({ url, auth: headers.get("authorization") });
        if (url.includes("/users")) return Response.json({ users: [{ id: "u1", email: "a" }] });
        if (url.includes("/brains")) {
          return Response.json({
            brains: [{ id: "b1", kind: "google-drive", status: "active", authScheme: "bearer" }],
          });
        }
        if (url.includes("/connections/google-drive")) {
          return Response.json({ connection: { status: "connected", email: "alice@example.com" } });
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
    const body = (await res.json()) as {
      brains: Array<{ authScheme?: string; kind: string }>;
      connections: { drive: { status: string } };
    };
    expect(body.connections.drive.status).toBe("connected");
    expect(body.brains).toEqual([{ id: "b1", kind: "google-drive", status: "active" }]);
    expect(calls).toHaveLength(4);
    expect(calls.every((call) => call.auth === `Bearer ${token}`)).toBe(true);
  });

  it("reports decoded session summary from HttpOnly token cookie", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = requestUrl(input);
      if (url.includes("/.well-known/jwks.json")) return Response.json(jwksBody);
      if (url.includes("/audit/chain")) return Response.json({ head: null });
      return Response.json({ users: [] });
    });
    vi.stubGlobal("fetch", fetchMock);
    const res = await app.request(
      "/v1/session",
      {
        headers: {
          cookie: `__Host-pact-admin-access=${signedToken};__Host-pact-audit-access=${signedAuditToken};__Host-pact-workspace=${workspaceId}`,
        },
      },
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { authenticated: boolean; claims: { email: string } };
    expect(body.authenticated).toBe(true);
    expect(body.claims.email).toBe("alice@example.com");
    expect(
      fetchMock.mock.calls.filter(([input]) =>
        requestUrl(input).includes("/.well-known/jwks.json"),
      ),
    ).toHaveLength(1);
  });

  it("normalizes issuer base URL while verifying session tokens", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = requestUrl(input);
        if (url.includes("/.well-known/jwks.json")) return Response.json(jwksBody);
        if (url.includes("/audit/chain")) return Response.json({ head: null });
        return Response.json({ users: [] });
      }),
    );
    const res = await app.request(
      "/v1/session",
      {
        headers: {
          cookie: `__Host-pact-admin-access=${signedToken};__Host-pact-audit-access=${signedAuditToken};__Host-pact-workspace=${workspaceId}`,
        },
      },
      { ...env, ISSUER_BASE_URL: "https://issuer.test/" },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { authenticated: boolean };
    expect(body.authenticated).toBe(true);
  });

  it("refetches workspace JWKS when cached keys miss the token kid", async () => {
    const rotatedIssuer = `${env.ISSUER_BASE_URL}/refetch`;
    const now = Math.floor(Date.now() / 1000);
    const rotatedToken = await new SignJWT({
      org: workspaceId,
      sub: "user-1",
      email: "alice@example.com",
      roles: ["admin"],
      groups: [],
    })
      .setProtectedHeader({ alg: "EdDSA", kid: "web-rotated-key" })
      .setIssuer(rotatedIssuer)
      .setAudience("pact-admin")
      .setJti("web-rotated-session-jti")
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(signingPrivateKey);
    const rotatedAuditToken = await new SignJWT({
      org: workspaceId,
      sub: "user-1",
      email: "alice@example.com",
      roles: ["auditor"],
      groups: [],
    })
      .setProtectedHeader({ alg: "EdDSA", kid: "web-rotated-key" })
      .setIssuer(rotatedIssuer)
      .setAudience("pact-audit")
      .setJti("web-rotated-audit-jti")
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(signingPrivateKey);
    const rotatedJwk = { ...(jwksBody.keys[0] as Record<string, unknown>), kid: "web-rotated-key" };
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = requestUrl(input);
      if (url.includes("/.well-known/jwks.json")) {
        const jwksCalls = fetchMock.mock.calls.filter(([callInput]) =>
          requestUrl(callInput).includes("/.well-known/jwks.json"),
        ).length;
        return Response.json(jwksCalls === 1 ? { keys: [] } : { keys: [rotatedJwk] });
      }
      if (url.includes("/audit/chain")) return Response.json({ head: null });
      return Response.json({ users: [] });
    });
    vi.stubGlobal("fetch", fetchMock);
    const res = await app.request(
      "/v1/session",
      {
        headers: {
          cookie: `__Host-pact-admin-access=${rotatedToken};__Host-pact-audit-access=${rotatedAuditToken};__Host-pact-workspace=${workspaceId}`,
        },
      },
      { ...env, ISSUER_BASE_URL: rotatedIssuer },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { authenticated: boolean };
    expect(body.authenticated).toBe(true);
    expect(
      fetchMock.mock.calls.filter(([input]) =>
        requestUrl(input).includes("/.well-known/jwks.json"),
      ),
    ).toHaveLength(2);
  });

  it("fails closed instead of 500 when workspace JWKS is malformed", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = requestUrl(input);
        if (url.includes("/.well-known/jwks.json")) {
          return new Response("not-json", {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        if (url.includes("/audit/chain")) return Response.json({ head: null });
        return Response.json({ users: [] });
      }),
    );
    const res = await app.request(
      "/v1/session",
      {
        headers: {
          cookie: `__Host-pact-admin-access=${signedToken};__Host-pact-audit-access=${signedAuditToken};__Host-pact-workspace=${workspaceId}`,
        },
      },
      { ...env, ISSUER_BASE_URL: `${env.ISSUER_BASE_URL}/malformed` },
    );
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ authenticated: false });
  });

  it("does not authenticate an unsigned token even if admin auth accepts it", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = requestUrl(input);
        if (url.includes("/.well-known/jwks.json")) return Response.json(jwksBody);
        if (url.includes("/audit/chain")) return Response.json({ head: null });
        return Response.json({ users: [] });
      }),
    );
    const res = await app.request(
      "/v1/session",
      {
        headers: {
          cookie: `__Host-pact-admin-access=${token};__Host-pact-audit-access=${signedAuditToken};__Host-pact-workspace=${workspaceId}`,
        },
      },
      env,
    );
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ authenticated: false });
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
          cookie: `__Host-pact-admin-access=${signedToken};__Host-pact-audit-access=${signedAuditToken};__Host-pact-workspace=${workspaceId}`,
        },
      },
      env,
    );
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ authenticated: false });
  });

  it("does not authenticate when the audit token is missing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ users: [] })),
    );
    const res = await app.request(
      "/v1/session",
      {
        headers: {
          cookie: `__Host-pact-admin-access=${signedToken};__Host-pact-workspace=${workspaceId}`,
        },
      },
      env,
    );
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ authenticated: false });
  });

  it("does not authenticate mixed-user admin and audit cookies", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = requestUrl(input);
        if (url.includes("/.well-known/jwks.json")) return Response.json(jwksBody);
        return Response.json({ users: [] });
      }),
    );
    const res = await app.request(
      "/v1/session",
      {
        headers: {
          cookie: `__Host-pact-admin-access=${signedToken};__Host-pact-audit-access=${signedOtherUserAuditToken};__Host-pact-workspace=${workspaceId}`,
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
        const url = requestUrl(input);
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
        const url = requestUrl(input);
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
