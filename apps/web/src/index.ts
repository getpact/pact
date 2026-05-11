import { isUuid, timingSafeEqualString } from "@getpact/core";
import { type Context, Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { decodeJwt } from "jose";

type Env = {
  ENVIRONMENT?: string;
  WEB_BASE_URL?: string;
  ISSUER_BASE_URL: string;
  ADMIN_API_BASE_URL: string;
  AUDIT_API_BASE_URL: string;
  ADMIN_AUDIENCE?: string;
  AUDIT_AUDIENCE?: string;
  GOOGLE_OAUTH_CLIENT_ID: string;
  GOOGLE_OAUTH_AUTHORIZATION_ENDPOINT?: string;
  WEB_ISSUER_SERVICE_TOKEN: string;
};

type AppContext = Context<{ Bindings: Env }>;

const ADMIN_ACCESS_COOKIE = "__Host-pact-admin-access";
const ADMIN_REFRESH_COOKIE = "__Host-pact-admin-refresh";
const AUDIT_ACCESS_COOKIE = "__Host-pact-audit-access";
const AUDIT_REFRESH_COOKIE = "__Host-pact-audit-refresh";
const WORKSPACE_COOKIE = "__Host-pact-workspace";
const CSRF_COOKIE = "__Host-pact-csrf";
const OAUTH_STATE_COOKIE = "__Host-pact-oauth-state";
const OAUTH_VERIFIER_COOKIE = "__Host-pact-oauth-verifier";
const OAUTH_WORKSPACE_COOKIE = "__Host-pact-oauth-workspace";

const GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const ADMIN_AUDIENCE = "pact-admin";
const TEN_MINUTES = 600;
const THIRTY_DAYS = 30 * 24 * 60 * 60;

const app = new Hono<{ Bindings: Env }>();

const dashboardSecurityHeaders = (production: boolean): Record<string, string> => ({
  "cache-control": "no-store",
  "content-security-policy":
    "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'",
  "cross-origin-resource-policy": "same-origin",
  "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  ...(production
    ? { "strict-transport-security": "max-age=31536000; includeSubDomains; preload" }
    : {}),
});

const applyDashboardHeaders = (c: AppContext): void => {
  const headers = dashboardSecurityHeaders(c.env.ENVIRONMENT === "production");
  for (const [k, v] of Object.entries(headers)) c.header(k, v);
};

app.use("*", async (c, next) => {
  applyDashboardHeaders(c);
  await next();
  applyDashboardHeaders(c);
});
app.use("/v1/*", bodyLimit({ maxSize: 8 * 1024 }));

app.onError((err, c) => {
  console.error(err);
  applyDashboardHeaders(c);
  return c.json({ error: "internal_error" }, 500);
});

const baseUrl = (raw: string): string => raw.replace(/\/+$/, "");

const webBaseUrl = (env: Env): string | null =>
  env.WEB_BASE_URL ? baseUrl(env.WEB_BASE_URL) : null;

const callbackUrl = (env: Env): string => {
  const base = webBaseUrl(env);
  if (!base) throw new Error("WEB_BASE_URL is required");
  return `${base}/v1/auth/google/callback`;
};

const urlFor = (base: string, path: string): string => new URL(path, baseUrl(base)).toString();

const fetchWithTimeout = async (
  input: RequestInfo | URL,
  init: RequestInit = {},
  timeoutMs = 10_000,
): Promise<Response> => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: init.signal ?? controller.signal });
  } finally {
    clearTimeout(timeout);
  }
};

const randomBase64Url = (bytes = 32): string => {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  let raw = "";
  for (const byte of data) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const sha256Base64Url = async (value: string): Promise<string> => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  let raw = "";
  for (const byte of new Uint8Array(digest)) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const parseCookies = (header: string | undefined): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const part of header?.split(";") ?? []) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(value);
    } catch {}
  }
  return out;
};

const cookie = (
  name: string,
  value: string,
  opts: {
    env: Env;
    httpOnly?: boolean;
    maxAge?: number;
    sameSite?: "Lax" | "Strict";
    path?: string;
  },
): string => {
  const attrs = [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${opts.path ?? "/"}`,
    `SameSite=${opts.sameSite ?? "Strict"}`,
  ];
  if (opts.maxAge !== undefined) attrs.push(`Max-Age=${opts.maxAge}`);
  if (opts.httpOnly) attrs.push("HttpOnly");
  attrs.push("Secure");
  return attrs.join("; ");
};

const clearCookie = (name: string, env: Env): string =>
  cookie(name, "", { env, maxAge: 0, httpOnly: true });

const appendCookie = (c: AppContext, value: string): void => {
  c.header("Set-Cookie", value, { append: true });
};

const sessionCookies = (c: AppContext) => parseCookies(c.req.header("Cookie"));

const trustedOrigin = (c: AppContext): string | null => {
  const base = webBaseUrl(c.env);
  return base ? new URL(base).origin : null;
};

const hasSameOriginSignal = (c: AppContext): boolean => {
  const expected = trustedOrigin(c);
  if (!expected) return false;
  const origin = c.req.header("Origin");
  if (origin) return origin === expected;
  const referer = c.req.header("Referer");
  if (!referer) return false;
  try {
    const actual = new URL(referer).origin;
    return actual === expected;
  } catch {
    return false;
  }
};

const requireCsrf = (c: AppContext): boolean => {
  const cookies = sessionCookies(c);
  const header = c.req.header("x-pact-csrf");
  return (
    !!header &&
    !!cookies[CSRF_COOKIE] &&
    timingSafeEqualString(header, cookies[CSRF_COOKIE]) &&
    hasSameOriginSignal(c)
  );
};

type TokenResponse = {
  token: string;
  refreshToken: string;
  exp: number;
  refreshExpiresAt?: string;
};

type TokenBundleResponse = {
  tokens: Record<string, TokenResponse>;
};

const storeSession = (
  c: AppContext,
  workspaceId: string,
  body: { admin: TokenResponse; audit: TokenResponse },
  csrfToken = randomBase64Url(24),
): void => {
  const now = Math.floor(Date.now() / 1000);
  const accessMaxAge = Math.max(Math.min(body.admin.exp, body.audit.exp) - now, 1);
  const refreshExp = [body.admin.refreshExpiresAt, body.audit.refreshExpiresAt]
    .map((value) => (value ? Math.floor(Date.parse(value) / 1000) : null))
    .filter((value): value is number => Number.isFinite(value));
  const refreshMaxAge =
    refreshExp.length > 0 ? Math.max(Math.min(...refreshExp) - now, 1) : THIRTY_DAYS;
  appendCookie(
    c,
    cookie(ADMIN_ACCESS_COOKIE, body.admin.token, {
      env: c.env,
      httpOnly: true,
      maxAge: accessMaxAge,
    }),
  );
  appendCookie(
    c,
    cookie(ADMIN_REFRESH_COOKIE, body.admin.refreshToken, {
      env: c.env,
      httpOnly: true,
      maxAge: refreshMaxAge,
    }),
  );
  appendCookie(
    c,
    cookie(AUDIT_ACCESS_COOKIE, body.audit.token, {
      env: c.env,
      httpOnly: true,
      maxAge: accessMaxAge,
    }),
  );
  appendCookie(
    c,
    cookie(AUDIT_REFRESH_COOKIE, body.audit.refreshToken, {
      env: c.env,
      httpOnly: true,
      maxAge: refreshMaxAge,
    }),
  );
  appendCookie(
    c,
    cookie(WORKSPACE_COOKIE, workspaceId, { env: c.env, httpOnly: true, maxAge: THIRTY_DAYS }),
  );
  appendCookie(
    c,
    cookie(CSRF_COOKIE, csrfToken, {
      env: c.env,
      httpOnly: true,
      maxAge: THIRTY_DAYS,
      sameSite: "Strict",
    }),
  );
};

const clearSession = (c: AppContext): void => {
  for (const name of [
    ADMIN_ACCESS_COOKIE,
    ADMIN_REFRESH_COOKIE,
    AUDIT_ACCESS_COOKIE,
    AUDIT_REFRESH_COOKIE,
    WORKSPACE_COOKIE,
    CSRF_COOKIE,
    OAUTH_STATE_COOKIE,
    OAUTH_VERIFIER_COOKIE,
    OAUTH_WORKSPACE_COOKIE,
  ]) {
    appendCookie(c, clearCookie(name, c.env));
  }
};

const tokenSummaryUnverified = (
  token: string,
  workspaceId: string,
): Record<string, unknown> | null => {
  try {
    const claims = decodeJwt(token);
    if (claims.org !== workspaceId) return null;
    return {
      workspaceId: claims.org,
      userId: claims.sub,
      email: claims.email,
      exp: claims.exp,
      roles: claims.roles,
      groups: claims.groups,
    };
  } catch {
    return null;
  }
};

const bearerFetch = async (url: string, token: string, init: RequestInit = {}): Promise<Response> =>
  fetchWithTimeout(url, {
    ...init,
    headers: {
      accept: "application/json",
      ...(init.headers ?? {}),
      authorization: `Bearer ${token}`,
    },
  });

app.get("/health", (c) => c.json({ ok: true }));

app.get("/", (c) => c.html(INDEX_HTML));
app.get("/assets/app.css", (c) => c.text(APP_CSS, 200, { "content-type": "text/css" }));
app.get("/assets/app.js", (c) => c.text(APP_JS, 200, { "content-type": "application/javascript" }));

app.post("/v1/auth/google/start", async (c) => {
  if (!webBaseUrl(c.env)) {
    return c.json({ error: "misconfigured", message: "WEB_BASE_URL is required" }, 503);
  }
  if (!hasSameOriginSignal(c)) return c.json({ error: "origin" }, 403);
  const body = await c.req.json<{ workspaceId: string }>().catch(() => ({ workspaceId: "" }));
  const workspaceId = body.workspaceId ?? "";
  if (!isUuid(workspaceId)) {
    return c.json({ error: "invalid_workspace" }, 400);
  }

  const state = randomBase64Url(32);
  const verifier = randomBase64Url(64);
  const challenge = await sha256Base64Url(verifier);
  const url = new URL(c.env.GOOGLE_OAUTH_AUTHORIZATION_ENDPOINT ?? GOOGLE_AUTH_ENDPOINT);
  url.searchParams.set("client_id", c.env.GOOGLE_OAUTH_CLIENT_ID);
  url.searchParams.set("redirect_uri", callbackUrl(c.env));
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");

  appendCookie(
    c,
    cookie(OAUTH_STATE_COOKIE, state, {
      env: c.env,
      httpOnly: true,
      maxAge: TEN_MINUTES,
      sameSite: "Lax",
    }),
  );
  appendCookie(
    c,
    cookie(OAUTH_VERIFIER_COOKIE, verifier, {
      env: c.env,
      httpOnly: true,
      maxAge: TEN_MINUTES,
      sameSite: "Lax",
    }),
  );
  appendCookie(
    c,
    cookie(OAUTH_WORKSPACE_COOKIE, workspaceId, {
      env: c.env,
      httpOnly: true,
      maxAge: TEN_MINUTES,
      sameSite: "Lax",
    }),
  );
  return c.json({ location: url.toString() });
});

app.get("/v1/auth/google/callback", async (c) => {
  if (!webBaseUrl(c.env)) {
    return c.json({ error: "misconfigured", message: "WEB_BASE_URL is required" }, 503);
  }
  const url = new URL(c.req.url);
  const code = url.searchParams.get("code") ?? "";
  const state = url.searchParams.get("state") ?? "";
  const cookies = sessionCookies(c);
  const expectedState = cookies[OAUTH_STATE_COOKIE];
  const verifier = cookies[OAUTH_VERIFIER_COOKIE];
  const workspaceId = cookies[OAUTH_WORKSPACE_COOKIE];
  if (
    !code ||
    !state ||
    !expectedState ||
    !timingSafeEqualString(state, expectedState) ||
    !verifier ||
    !workspaceId
  ) {
    clearSession(c);
    return c.html(LOGIN_FAILED_HTML, 401);
  }

  const adminAudience = c.env.ADMIN_AUDIENCE ?? ADMIN_AUDIENCE;
  const auditAudience = c.env.AUDIT_AUDIENCE ?? "pact-audit";
  const exchange = await fetchWithTimeout(
    urlFor(c.env.ISSUER_BASE_URL, "/v1/oauth/google/session"),
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        "x-pact-web-service-token": c.env.WEB_ISSUER_SERVICE_TOKEN,
      },
      body: JSON.stringify({
        workspaceId,
        code,
        codeVerifier: verifier,
        redirectUri: callbackUrl(c.env),
        audiences: [adminAudience, auditAudience],
      }),
    },
  );
  if (!exchange.ok) {
    clearSession(c);
    return c.html(LOGIN_FAILED_HTML, 401);
  }
  const body = (await exchange.json()) as TokenBundleResponse;
  const admin = body.tokens[adminAudience];
  const audit = body.tokens[auditAudience];
  if (!admin || !audit) {
    clearSession(c);
    return c.html(LOGIN_FAILED_HTML, 401);
  }
  storeSession(c, workspaceId, { admin, audit });
  appendCookie(c, clearCookie(OAUTH_STATE_COOKIE, c.env));
  appendCookie(c, clearCookie(OAUTH_VERIFIER_COOKIE, c.env));
  appendCookie(c, clearCookie(OAUTH_WORKSPACE_COOKIE, c.env));
  return c.redirect("/", 302);
});

app.get("/v1/session", async (c) => {
  const cookies = sessionCookies(c);
  const token = cookies[ADMIN_ACCESS_COOKIE];
  const workspaceId = cookies[WORKSPACE_COOKIE];
  if (!token || !workspaceId) return c.json({ authenticated: false });
  const authCheck = await bearerFetch(
    `${baseUrl(c.env.ADMIN_API_BASE_URL)}/v1/workspaces/${workspaceId}/users`,
    token,
  );
  if (!authCheck.ok) return c.json({ authenticated: false });
  const claims = tokenSummaryUnverified(token, workspaceId);
  if (!claims) return c.json({ authenticated: false });
  return c.json({ authenticated: true, workspaceId, claims, csrfToken: cookies[CSRF_COOKIE] });
});

app.post("/v1/session/refresh", async (c) => {
  if (!requireCsrf(c)) return c.json({ error: "csrf" }, 403);
  const cookies = sessionCookies(c);
  const adminRefreshToken = cookies[ADMIN_REFRESH_COOKIE];
  const auditRefreshToken = cookies[AUDIT_REFRESH_COOKIE];
  const workspaceId = cookies[WORKSPACE_COOKIE];
  if (!adminRefreshToken || !auditRefreshToken || !workspaceId) {
    return c.json({ error: "not_authenticated" }, 401);
  }
  const refresh = (refreshToken: string, audience: string) =>
    fetchWithTimeout(urlFor(c.env.ISSUER_BASE_URL, "/v1/refresh"), {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        workspaceId,
        refreshToken,
        audience,
      }),
    });
  const adminAudience = c.env.ADMIN_AUDIENCE ?? ADMIN_AUDIENCE;
  const auditAudience = c.env.AUDIT_AUDIENCE ?? "pact-audit";
  const [adminRes, auditRes] = await Promise.all([
    refresh(adminRefreshToken, adminAudience),
    refresh(auditRefreshToken, auditAudience),
  ]);
  if (!adminRes.ok || !auditRes.ok) {
    clearSession(c);
    return c.json({ error: "not_authenticated" }, 401);
  }
  const admin = (await adminRes.json()) as TokenResponse;
  const audit = (await auditRes.json()) as TokenResponse;
  storeSession(c, workspaceId, { admin, audit }, cookies[CSRF_COOKIE]);
  return c.json({ ok: true });
});

app.delete("/v1/session", (c) => {
  if (!requireCsrf(c)) return c.json({ error: "csrf" }, 403);
  clearSession(c);
  return c.json({ ok: true });
});

app.get("/v1/workspace/status", async (c) => {
  const cookies = sessionCookies(c);
  const adminToken = cookies[ADMIN_ACCESS_COOKIE];
  const auditToken = cookies[AUDIT_ACCESS_COOKIE];
  const workspaceId = cookies[WORKSPACE_COOKIE];
  if (!adminToken || !auditToken || !workspaceId) {
    return c.json({ error: "not_authenticated" }, 401);
  }

  const usersRes = await bearerFetch(
    `${baseUrl(c.env.ADMIN_API_BASE_URL)}/v1/workspaces/${workspaceId}/users`,
    adminToken,
  );
  if (!usersRes.ok) return c.json({ error: "admin_unavailable", status: usersRes.status }, 502);
  const usersBody = (await usersRes.json()) as { users?: Array<{ id: string; email: string }> };

  const brainsRes = await bearerFetch(
    `${baseUrl(c.env.ADMIN_API_BASE_URL)}/v1/workspaces/${workspaceId}/brains`,
    adminToken,
  );
  if (!brainsRes.ok) return c.json({ error: "admin_unavailable", status: brainsRes.status }, 502);
  const brainsBody = (await brainsRes.json()) as {
    brains?: Array<{ id: string; kind: string; status: string; authScheme: string }>;
  };

  const chainRes = await bearerFetch(
    `${baseUrl(c.env.AUDIT_API_BASE_URL)}/v1/workspaces/${workspaceId}/audit/chain`,
    auditToken,
  );
  if (!chainRes.ok) return c.json({ error: "audit_unavailable", status: chainRes.status }, 502);
  const chainBody = (await chainRes.json()) as { head?: unknown };
  const brains = brainsBody.brains ?? [];
  const drive = brains.find((brain) => brain.kind === "google-drive");

  return c.json({
    workspaceId,
    users: { count: usersBody.users?.length ?? 0 },
    connections: {
      drive: drive ? { status: drive.status, brainId: drive.id } : { status: "not_configured" },
    },
    brains,
    audit: { head: chainBody.head ?? null },
  });
});

const INDEX_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Pact Dashboard</title>
    <link rel="stylesheet" href="/assets/app.css">
  </head>
  <body>
    <main class="shell">
      <header class="topbar">
        <div>
          <p class="eyebrow">Pact</p>
          <h1>Workspace control plane</h1>
        </div>
        <button id="logout" class="ghost hidden" type="button">Sign out</button>
      </header>
      <section id="login" class="panel">
        <h2>Sign in</h2>
        <p>Use Google to access a workspace, connect sources, and configure MCP for agents.</p>
        <form id="login-form">
          <label for="workspace-id">Workspace ID</label>
          <div class="row">
            <input id="workspace-id" name="workspaceId" autocomplete="off" required>
            <button type="submit">Continue with Google</button>
          </div>
        </form>
      </section>
      <section id="dashboard" class="hidden">
        <div class="grid">
          <article class="panel">
            <h2>Session</h2>
            <dl id="session-details"></dl>
          </article>
          <article class="panel">
            <h2>Google Drive</h2>
            <p id="drive-status">Checking connection...</p>
            <button type="button" disabled>Connect Drive</button>
          </article>
          <article class="panel">
            <h2>MCP setup</h2>
            <p id="mcp-status">Install instructions will appear after Drive indexing is enabled.</p>
          </article>
          <article class="panel">
            <h2>Audit</h2>
            <p id="audit-status">Checking audit chain...</p>
          </article>
        </div>
      </section>
      <p id="error" role="alert"></p>
    </main>
    <script src="/assets/app.js" type="module"></script>
  </body>
</html>`;

const LOGIN_FAILED_HTML = `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Pact login failed</title></head>
  <body><p>Login failed. Return to the dashboard and try again.</p></body>
</html>`;

const APP_CSS = `
:root {
  color-scheme: light;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #f6f7f9;
  color: #162033;
}
body {
  margin: 0;
}
button, input {
  font: inherit;
}
.shell {
  max-width: 1120px;
  margin: 0 auto;
  padding: 32px 20px;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 28px;
}
.eyebrow {
  margin: 0 0 4px;
  color: #596579;
  font-size: 13px;
  text-transform: uppercase;
}
h1, h2, p {
  margin-top: 0;
}
h1 {
  margin-bottom: 0;
  font-size: 32px;
}
h2 {
  font-size: 18px;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 16px;
}
.panel {
  background: #ffffff;
  border: 1px solid #d8dde6;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
}
.row {
  display: flex;
  gap: 8px;
  align-items: stretch;
}
label {
  display: block;
  margin-bottom: 8px;
  font-weight: 600;
}
input {
  min-width: 0;
  flex: 1;
  border: 1px solid #b8c0cc;
  border-radius: 6px;
  padding: 10px 12px;
}
button {
  border: 0;
  border-radius: 6px;
  padding: 10px 14px;
  background: #155eef;
  color: #ffffff;
  cursor: pointer;
}
button:disabled {
  cursor: not-allowed;
  background: #9aa4b2;
}
.ghost {
  background: transparent;
  color: #25324a;
  border: 1px solid #b8c0cc;
}
.hidden {
  display: none;
}
dl {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 8px 12px;
  margin: 0;
}
dt {
  color: #596579;
}
dd {
  margin: 0;
  min-width: 0;
  overflow-wrap: anywhere;
}
#error {
  margin-top: 16px;
  color: #b42318;
}
@media (max-width: 640px) {
  .topbar, .row {
    align-items: stretch;
    flex-direction: column;
  }
}
`;

const APP_JS = `
const $ = (id) => document.getElementById(id);
let csrfToken = "";

const requestJson = async (path, init = {}) => {
  const res = await fetch(path, {
    ...init,
    headers: {
      accept: "application/json",
      ...(init.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(path + " returned " + res.status);
  return res.json();
};

const renderSession = (session) => {
  const details = $("session-details");
  const claims = session.claims ?? {};
  details.innerHTML = "";
  for (const [label, value] of [
    ["Workspace", session.workspaceId],
    ["Email", claims.email],
    ["Roles", Array.isArray(claims.roles) ? claims.roles.join(", ") : ""],
  ]) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value || "Unknown";
    details.append(dt, dd);
  }
};

const renderStatus = (status) => {
  const drive = status.connections?.drive;
  $("drive-status").textContent =
    drive?.status === "not_configured"
      ? "Drive is not connected yet."
      : "Drive connection status: " + drive.status;
  $("audit-status").textContent = status.audit?.head
    ? "Audit chain has an active head."
    : "No audit head found yet.";
};

const load = async () => {
  $("error").textContent = "";
  const session = await requestJson("/v1/session");
  if (!session.authenticated) {
    $("login").classList.remove("hidden");
    $("dashboard").classList.add("hidden");
    $("logout").classList.add("hidden");
    return;
  }
  $("login").classList.add("hidden");
  $("dashboard").classList.remove("hidden");
  $("logout").classList.remove("hidden");
  csrfToken = session.csrfToken ?? "";
  renderSession(session);
  try {
    renderStatus(await requestJson("/v1/workspace/status"));
  } catch (error) {
    $("error").textContent = error instanceof Error ? error.message : "Status failed";
  }
};

$("login-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const workspaceId = new FormData(event.currentTarget).get("workspaceId");
  requestJson("/v1/auth/google/start", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ workspaceId }),
  })
    .then((body) => {
      window.location.href = body.location;
    })
    .catch((error) => {
      $("error").textContent = error instanceof Error ? error.message : "Login failed";
    });
});

$("logout").addEventListener("click", async () => {
  await fetch("/v1/session", { method: "DELETE", headers: { "x-pact-csrf": csrfToken } });
  await load();
});

load().catch((error) => {
  $("error").textContent = error instanceof Error ? error.message : "Dashboard failed";
});
`;

export default app;
