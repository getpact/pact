import { isUuid, timingSafeEqualString } from "@getpact/core";
import { type Context, Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { decodeProtectedHeader, importJWK, type JWK, jwtVerify } from "jose";

type Env = {
  ENVIRONMENT?: string;
  WEB_BASE_URL?: string;
  WEB_OAUTH_CALLBACK_PATH?: string;
  WEB_DRIVE_OAUTH_CALLBACK_PATH?: string;
  WEB_DEV_ROUTE_ORIGIN?: string;
  WEB_DEFAULT_WORKSPACE_ID?: string;
  ISSUER_BASE_URL: string;
  ADMIN_API_BASE_URL: string;
  AUDIT_API_BASE_URL: string;
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
const DRIVE_STATE_COOKIE = "__Host-pact-drive-state";
const DRIVE_VERIFIER_COOKIE = "__Host-pact-drive-verifier";
const DRIVE_WORKSPACE_COOKIE = "__Host-pact-drive-workspace";
const DRIVE_NONCE_COOKIE = "__Host-pact-drive-nonce";

const GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const ADMIN_AUDIENCE = "pact-admin";
const AUDIT_AUDIENCE = "pact-audit";
const TEN_MINUTES = 600;
const THIRTY_DAYS = 30 * 24 * 60 * 60;
const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
const JWKS_KID_MISS_TTL_MS = 30 * 1000;

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
  const path = env.WEB_OAUTH_CALLBACK_PATH ?? "/v1/auth/google/callback";
  return `${base}/${path.replace(/^\/+/, "")}`;
};

const driveCallbackUrl = (env: Env): string => {
  const base = webBaseUrl(env);
  if (!base) throw new Error("WEB_BASE_URL is required");
  const path = env.WEB_DRIVE_OAUTH_CALLBACK_PATH ?? "/v1/connections/google-drive/callback";
  return `${base}/${path.replace(/^\/+/, "")}`;
};

const urlFor = (base: string, path: string): string =>
  `${baseUrl(base)}/${path.replace(/^\/+/, "")}`;

const configuredSecret = (value: string | undefined): boolean =>
  !!value && !value.startsWith("replace-with") && !value.startsWith("changeme");

const configuredGoogleClient = (value: string | undefined): boolean =>
  typeof value === "string" && configuredSecret(value) && !value.startsWith("local-dev");

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

const isLoopbackHost = (hostname: string): boolean =>
  hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";

const requestIsLoopback = (c: AppContext): boolean => {
  const requestUrl = new URL(c.req.url);
  if (isLoopbackHost(requestUrl.hostname)) return true;
  const host = c.req.header("Host")?.split(":")[0] ?? "";
  return isLoopbackHost(host);
};

const loopbackOriginAliases = (url: URL): string[] => {
  if (!isLoopbackHost(url.hostname)) return [];
  const port = url.port ? `:${url.port}` : "";
  return [`${url.protocol}//localhost${port}`, `${url.protocol}//127.0.0.1${port}`];
};

const trustedOrigins = (c: AppContext): Set<string> => {
  const origins = new Set<string>();
  const base = webBaseUrl(c.env);
  if (base) {
    const baseParsed = new URL(base);
    origins.add(baseParsed.origin);
    if (c.env.ENVIRONMENT !== "production") {
      for (const alias of loopbackOriginAliases(baseParsed)) origins.add(alias);
    }
  }
  if (c.env.ENVIRONMENT !== "production") {
    if (c.env.WEB_DEV_ROUTE_ORIGIN) {
      origins.add(new URL(c.env.WEB_DEV_ROUTE_ORIGIN).origin);
    }
    const requestUrl = new URL(c.req.url);
    if (isLoopbackHost(requestUrl.hostname)) {
      origins.add(requestUrl.origin);
      for (const alias of loopbackOriginAliases(requestUrl)) origins.add(alias);
    }
  }
  return origins;
};

const hasSameOriginSignal = (c: AppContext): boolean => {
  const expected = trustedOrigins(c);
  if (expected.size === 0) return false;
  const isLocalDevRequest = c.env.ENVIRONMENT === "development" && requestIsLoopback(c);
  if (
    isLocalDevRequest &&
    c.req.header("x-pact-local-dev") === "1" &&
    c.req.header("Sec-Fetch-Site") !== "cross-site"
  ) {
    return true;
  }
  const origin = c.req.header("Origin");
  if (isLocalDevRequest && (!origin || origin === "null")) return true;
  if (origin) return expected.has(origin);
  const referer = c.req.header("Referer");
  if (!referer) {
    return isLocalDevRequest;
  }
  try {
    const actual = new URL(referer).origin;
    return expected.has(actual);
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

type JwksResponse = {
  keys?: JWK[];
};

const jwksCache = new Map<string, { expiresAt: number; body: JwksResponse }>();
const jwksKidMissCache = new Map<string, number>();

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
    DRIVE_STATE_COOKIE,
    DRIVE_VERIFIER_COOKIE,
    DRIVE_WORKSPACE_COOKIE,
    DRIVE_NONCE_COOKIE,
  ]) {
    appendCookie(c, clearCookie(name, c.env));
  }
};

const clearOAuthAttempt = (c: AppContext): void => {
  for (const name of [OAUTH_STATE_COOKIE, OAUTH_VERIFIER_COOKIE, OAUTH_WORKSPACE_COOKIE]) {
    appendCookie(c, clearCookie(name, c.env));
  }
};

const clearDriveOAuthAttempt = (c: AppContext): void => {
  for (const name of [
    DRIVE_STATE_COOKIE,
    DRIVE_VERIFIER_COOKIE,
    DRIVE_WORKSPACE_COOKIE,
    DRIVE_NONCE_COOKIE,
  ]) {
    appendCookie(c, clearCookie(name, c.env));
  }
};

const loadWorkspaceJwks = async (
  env: Env,
  workspaceId: string,
  opts: { force?: boolean } = {},
): Promise<JwksResponse | null> => {
  const issuer = baseUrl(env.ISSUER_BASE_URL);
  const key = `${issuer}|${workspaceId}`;
  const cached = jwksCache.get(key);
  if (!opts.force && cached && cached.expiresAt > Date.now()) {
    jwksCache.delete(key);
    jwksCache.set(key, cached);
    return cached.body;
  }

  try {
    const jwksRes = await fetchWithTimeout(
      urlFor(issuer, `/v1/workspaces/${workspaceId}/.well-known/jwks.json`),
    );
    if (!jwksRes.ok) return null;
    const body = (await jwksRes.json()) as JwksResponse;
    jwksCache.set(key, { expiresAt: Date.now() + JWKS_CACHE_TTL_MS, body });
    if (jwksCache.size > 200) {
      const oldest = jwksCache.keys().next().value;
      if (oldest) jwksCache.delete(oldest);
    }
    return body;
  } catch {
    return null;
  }
};

const tokenKid = (token: string): string | null => {
  try {
    return decodeProtectedHeader(token).kid ?? null;
  } catch {
    return null;
  }
};

const jwksHasKid = (kid: string | null, jwksBody: JwksResponse): boolean =>
  !!kid && !!jwksBody.keys?.some((key) => key.kid === kid);

const kidMissCacheKey = (env: Env, workspaceId: string, kid: string): string =>
  `${baseUrl(env.ISSUER_BASE_URL)}|${workspaceId}|${kid}`;

const shouldRefetchForMissingKids = (env: Env, workspaceId: string, kids: string[]): boolean => {
  const now = Date.now();
  for (const kid of kids) {
    const expiresAt = jwksKidMissCache.get(kidMissCacheKey(env, workspaceId, kid));
    if (!expiresAt || expiresAt <= now) return true;
  }
  return false;
};

const cacheMissingKids = (
  env: Env,
  workspaceId: string,
  kids: string[],
  jwksBody: JwksResponse,
): void => {
  const expiresAt = Date.now() + JWKS_KID_MISS_TTL_MS;
  for (const kid of kids) {
    if (!jwksHasKid(kid, jwksBody)) {
      jwksKidMissCache.set(kidMissCacheKey(env, workspaceId, kid), expiresAt);
    }
  }
  if (jwksKidMissCache.size > 500) {
    const now = Date.now();
    for (const [key, value] of jwksKidMissCache) {
      if (value <= now) jwksKidMissCache.delete(key);
    }
    while (jwksKidMissCache.size > 500) {
      const oldest = jwksKidMissCache.keys().next().value;
      if (!oldest) break;
      jwksKidMissCache.delete(oldest);
    }
  }
};

const stringArrayClaim = (value: unknown): string[] | null =>
  Array.isArray(value) && value.every((item) => typeof item === "string") ? value : null;

const tokenSummaryVerified = async (
  env: Env,
  token: string,
  workspaceId: string,
  audience: string,
  jwksBody: JwksResponse,
): Promise<Record<string, unknown> | null> => {
  try {
    const kid = decodeProtectedHeader(token).kid;
    if (!kid) return null;
    const jwk = jwksBody.keys?.find((key) => key.kid === kid);
    if (!jwk) return null;
    const publicKey = await importJWK(jwk, "EdDSA");
    const { payload: claims } = await jwtVerify(token, publicKey, {
      issuer: baseUrl(env.ISSUER_BASE_URL),
      audience,
      algorithms: ["EdDSA"],
    });
    if (claims.org !== workspaceId) return null;
    if (
      typeof claims.org !== "string" ||
      typeof claims.sub !== "string" ||
      typeof claims.email !== "string" ||
      typeof claims.exp !== "number"
    ) {
      return null;
    }
    const roles = stringArrayClaim(claims.roles);
    const groups = stringArrayClaim(claims.groups);
    if (!roles || !groups) return null;
    return {
      workspaceId: claims.org,
      userId: claims.sub,
      email: claims.email,
      exp: claims.exp,
      roles,
      groups,
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

const escapeHtml = (value: string): string =>
  value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });

app.get("/health", (c) => c.json({ ok: true }));

app.get("/v1/config", (c) =>
  c.json({
    mode: c.env.ENVIRONMENT === "production" ? "production" : "nonproduction",
    defaultWorkspaceId: isUuid(c.env.WEB_DEFAULT_WORKSPACE_ID ?? "")
      ? c.env.WEB_DEFAULT_WORKSPACE_ID
      : null,
    oauthConfigured:
      configuredGoogleClient(c.env.GOOGLE_OAUTH_CLIENT_ID) &&
      configuredSecret(c.env.WEB_ISSUER_SERVICE_TOKEN),
  }),
);

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

const handleGoogleCallback = async (c: AppContext) => {
  const callbackCookies = sessionCookies(c);
  if (callbackCookies[DRIVE_STATE_COOKIE] && !callbackCookies[OAUTH_STATE_COOKIE]) {
    return handleDriveCallback(c);
  }
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
    clearOAuthAttempt(c);
    return c.html(
      loginFailedHtml("The Google sign-in link expired. Start sign-in again from the dashboard."),
      401,
    );
  }

  let exchange: Response;
  try {
    exchange = await fetchWithTimeout(urlFor(c.env.ISSUER_BASE_URL, "/v1/oauth/google/session"), {
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
        audiences: [ADMIN_AUDIENCE, AUDIT_AUDIENCE],
      }),
    });
  } catch (err) {
    console.error("oauth_session_exchange_failed", err);
    clearOAuthAttempt(c);
    return c.html(
      loginFailedHtml(
        "The issuer could not complete the OAuth exchange. For local testing, make sure the local issuer is running and uses the same Google client secret, redirect URI, and service token.",
      ),
      502,
    );
  }
  if (!exchange.ok) {
    const errorBody = await exchange
      .json<{ error?: string; message?: string }>()
      .catch((): { error?: string; message?: string } => ({}));
    clearOAuthAttempt(c);
    const message =
      errorBody.error === "user_not_in_workspace"
        ? "Your Google account is not a member of this workspace."
        : errorBody.error === "google_identity_mismatch"
          ? "This Google account is already linked to a different workspace user."
          : errorBody.error === "google_email_not_authoritative"
            ? "Google could not prove this email address for first-time workspace binding."
            : errorBody.error === "invalid_grant"
              ? "Google rejected the sign-in code. Start sign-in again from the dashboard."
              : errorBody.message ||
                (exchange.status === 503
                  ? "The issuer is misconfigured or unavailable."
                  : exchange.status === 502
                    ? "Google sign-in is temporarily unavailable."
                    : "The issuer rejected this Google sign-in request.");
    const status =
      exchange.status === 400 ||
      exchange.status === 401 ||
      exchange.status === 403 ||
      exchange.status === 429 ||
      exchange.status === 500 ||
      exchange.status === 502 ||
      exchange.status === 503 ||
      exchange.status === 504
        ? exchange.status
        : 502;
    return c.html(loginFailedHtml(message), status);
  }
  const body = (await exchange.json()) as TokenBundleResponse;
  const admin = body.tokens[ADMIN_AUDIENCE];
  const audit = body.tokens[AUDIT_AUDIENCE];
  if (!admin || !audit) {
    clearOAuthAttempt(c);
    return c.html(loginFailedHtml("The issuer returned an incomplete dashboard session."), 502);
  }
  storeSession(c, workspaceId, { admin, audit });
  clearOAuthAttempt(c);
  return c.redirect("/", 302);
};

app.get("/v1/auth/google/callback", handleGoogleCallback);
app.get("/oauth/oidc/callback", handleGoogleCallback);

app.post("/v1/connections/google-drive/start", async (c) => {
  if (!webBaseUrl(c.env)) {
    return c.json({ error: "misconfigured", message: "WEB_BASE_URL is required" }, 503);
  }
  if (!requireCsrf(c)) return c.json({ error: "csrf" }, 403);

  const cookies = sessionCookies(c);
  const adminToken = cookies[ADMIN_ACCESS_COOKIE];
  const workspaceId = cookies[WORKSPACE_COOKIE];
  if (!adminToken || !workspaceId || !isUuid(workspaceId)) {
    return c.json({ error: "not_authenticated" }, 401);
  }

  const state = randomBase64Url(32);
  const nonce = randomBase64Url(32);
  const verifier = randomBase64Url(64);
  const challenge = await sha256Base64Url(verifier);
  const url = new URL(c.env.GOOGLE_OAUTH_AUTHORIZATION_ENDPOINT ?? GOOGLE_AUTH_ENDPOINT);
  url.searchParams.set("client_id", c.env.GOOGLE_OAUTH_CLIENT_ID);
  url.searchParams.set("redirect_uri", driveCallbackUrl(c.env));
  url.searchParams.set("response_type", "code");
  url.searchParams.set(
    "scope",
    "openid email profile https://www.googleapis.com/auth/drive.readonly",
  );
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");

  appendCookie(
    c,
    cookie(DRIVE_STATE_COOKIE, state, {
      env: c.env,
      httpOnly: true,
      maxAge: TEN_MINUTES,
      sameSite: "Lax",
    }),
  );
  appendCookie(
    c,
    cookie(DRIVE_VERIFIER_COOKIE, verifier, {
      env: c.env,
      httpOnly: true,
      maxAge: TEN_MINUTES,
      sameSite: "Lax",
    }),
  );
  appendCookie(
    c,
    cookie(DRIVE_WORKSPACE_COOKIE, workspaceId, {
      env: c.env,
      httpOnly: true,
      maxAge: TEN_MINUTES,
      sameSite: "Lax",
    }),
  );
  appendCookie(
    c,
    cookie(DRIVE_NONCE_COOKIE, nonce, {
      env: c.env,
      httpOnly: true,
      maxAge: TEN_MINUTES,
      sameSite: "Lax",
    }),
  );

  return c.json({ location: url.toString() });
});

async function handleDriveCallback(c: AppContext) {
  const url = new URL(c.req.url);
  const code = url.searchParams.get("code") ?? "";
  const state = url.searchParams.get("state") ?? "";
  const cookies = sessionCookies(c);
  const expectedState = cookies[DRIVE_STATE_COOKIE];
  const verifier = cookies[DRIVE_VERIFIER_COOKIE];
  const nonce = cookies[DRIVE_NONCE_COOKIE];
  const workspaceId = cookies[DRIVE_WORKSPACE_COOKIE];
  const adminToken = cookies[ADMIN_ACCESS_COOKIE];
  if (
    !code ||
    !state ||
    !expectedState ||
    !timingSafeEqualString(state, expectedState) ||
    !verifier ||
    !nonce ||
    !workspaceId ||
    !adminToken ||
    !isUuid(workspaceId)
  ) {
    clearDriveOAuthAttempt(c);
    return c.html(
      loginFailedHtml("The Google Drive connection link expired. Start again from the dashboard."),
      401,
    );
  }

  const response = await bearerFetch(
    `${baseUrl(c.env.ADMIN_API_BASE_URL)}/v1/workspaces/${workspaceId}/connections/google-drive/oauth`,
    adminToken,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        code,
        codeVerifier: verifier,
        nonce,
        redirectUri: driveCallbackUrl(c.env),
      }),
    },
  ).catch(() => null);
  clearDriveOAuthAttempt(c);
  if (!response?.ok) {
    return c.html(
      loginFailedHtml("Google Drive could not be connected for this workspace user."),
      response?.status === 400 || response?.status === 401 || response?.status === 403
        ? response.status
        : 502,
    );
  }
  return c.redirect("/", 302);
}

app.get("/v1/connections/google-drive/callback", handleDriveCallback);

app.delete("/v1/connections/google-drive", async (c) => {
  if (!requireCsrf(c)) return c.json({ error: "csrf" }, 403);
  const cookies = sessionCookies(c);
  const adminToken = cookies[ADMIN_ACCESS_COOKIE];
  const workspaceId = cookies[WORKSPACE_COOKIE];
  if (!adminToken || !workspaceId || !isUuid(workspaceId)) {
    return c.json({ error: "not_authenticated" }, 401);
  }
  const response = await bearerFetch(
    `${baseUrl(c.env.ADMIN_API_BASE_URL)}/v1/workspaces/${workspaceId}/connections/google-drive`,
    adminToken,
    { method: "DELETE" },
  ).catch(() => null);
  if (!response?.ok) {
    return c.json({ error: "drive_disconnect_failed" }, response?.status === 401 ? 401 : 502);
  }
  return c.json({ ok: true });
});

app.get("/v1/session", async (c) => {
  const cookies = sessionCookies(c);
  const token = cookies[ADMIN_ACCESS_COOKIE];
  const auditToken = cookies[AUDIT_ACCESS_COOKIE];
  const workspaceId = cookies[WORKSPACE_COOKIE];
  if (!token || !auditToken || !workspaceId) return c.json({ authenticated: false });
  if (!isUuid(workspaceId)) return c.json({ authenticated: false });
  const jwksBody = await loadWorkspaceJwks(c.env, workspaceId);
  if (!jwksBody) return c.json({ authenticated: false });
  const tokenKids = [tokenKid(token), tokenKid(auditToken)];
  const missingKids = tokenKids.filter((kid) => kid && !jwksHasKid(kid, jwksBody)) as string[];
  const verifierJwks =
    missingKids.length === 0 || !shouldRefetchForMissingKids(c.env, workspaceId, missingKids)
      ? jwksBody
      : await loadWorkspaceJwks(c.env, workspaceId, { force: true });
  if (!verifierJwks) return c.json({ authenticated: false });
  cacheMissingKids(c.env, workspaceId, missingKids, verifierJwks);
  const claims = await tokenSummaryVerified(
    c.env,
    token,
    workspaceId,
    ADMIN_AUDIENCE,
    verifierJwks,
  );
  if (!claims) return c.json({ authenticated: false });
  const auditClaims = await tokenSummaryVerified(
    c.env,
    auditToken,
    workspaceId,
    AUDIT_AUDIENCE,
    verifierJwks,
  );
  if (!auditClaims) return c.json({ authenticated: false });
  if (claims.userId !== auditClaims.userId || claims.email !== auditClaims.email) {
    return c.json({ authenticated: false });
  }
  const authCheck = await bearerFetch(
    `${baseUrl(c.env.ADMIN_API_BASE_URL)}/v1/workspaces/${workspaceId}/users`,
    token,
  );
  if (!authCheck.ok) return c.json({ authenticated: false });
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
  const [adminRes, auditRes] = await Promise.all([
    refresh(adminRefreshToken, ADMIN_AUDIENCE),
    refresh(auditRefreshToken, AUDIT_AUDIENCE),
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
  if (!adminToken || !auditToken || !workspaceId || !isUuid(workspaceId)) {
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
    brains?: Array<{ id: string; kind: string; status: string }>;
  };

  const driveRes = await bearerFetch(
    `${baseUrl(c.env.ADMIN_API_BASE_URL)}/v1/workspaces/${workspaceId}/connections/google-drive`,
    adminToken,
  );
  if (!driveRes.ok) return c.json({ error: "admin_unavailable", status: driveRes.status }, 502);
  const driveBody = (await driveRes.json()) as {
    connection?: {
      id?: string;
      status?: string;
      email?: string;
      scopes?: string[];
      expiresAt?: string;
      connectedAt?: string;
    };
  };

  const chainRes = await bearerFetch(
    `${baseUrl(c.env.AUDIT_API_BASE_URL)}/v1/workspaces/${workspaceId}/audit/chain`,
    auditToken,
  );
  if (!chainRes.ok) return c.json({ error: "audit_unavailable", status: chainRes.status }, 502);
  const chainBody = (await chainRes.json()) as { head?: unknown };
  const brains = (brainsBody.brains ?? []).map((brain) => ({
    id: brain.id,
    kind: brain.kind,
    status: brain.status,
  }));

  return c.json({
    workspaceId,
    users: { count: usersBody.users?.length ?? 0 },
    brains,
    connections: {
      drive: driveBody.connection ?? { status: "not_configured" },
    },
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
          <p class="eyebrow">pact v0.1</p>
          <h1>Authorization for company brains.</h1>
          <p class="lede">Sign in, connect sources, and keep agent access tied to identity and audit proof.</p>
        </div>
        <button id="logout" class="ghost hidden" type="button">Sign out</button>
      </header>
      <section id="loading" class="panel" aria-busy="true">
        <div class="panel-head">
          <span class="dots" aria-hidden="true"><span></span><span></span><span></span></span>
          <span>session</span>
          <span class="panel-meta">checking</span>
        </div>
        <div class="panel-body">
          <p class="terminal-line">awaiting workspace session...</p>
        </div>
      </section>
      <section id="login" class="panel hidden">
        <div class="panel-head">
          <span class="dots" aria-hidden="true"><span></span><span></span><span></span></span>
          <span>google login</span>
          <span class="panel-meta">workspace scoped</span>
        </div>
        <div class="panel-body login-grid">
          <div>
            <h2>Open a workspace.</h2>
            <p>Google proves the human. Pact mints workspace-scoped tokens for admin and audit surfaces.</p>
            <p id="oauth-help" class="notice hidden"></p>
          </div>
          <form id="login-form">
            <p id="workspace-summary" class="workspace-summary hidden"></p>
            <div id="workspace-field">
              <label for="workspace-id">workspace id</label>
              <input id="workspace-id" name="workspaceId" autocomplete="off" autocapitalize="none" spellcheck="false" inputmode="text" required aria-describedby="workspace-help" placeholder="00000000-0000-4000-8000-000000000000">
              <p id="workspace-help" class="help">Paste the UUID for the workspace you want to administer.</p>
            </div>
            <button id="login-submit" type="submit">Continue with Google</button>
          </form>
        </div>
      </section>
      <section id="dashboard" class="hidden">
        <div class="metrics">
          <article class="metric">
            <span class="label">workspace</span>
            <strong id="metric-workspace">-</strong>
          </article>
          <article class="metric">
            <span class="label">users</span>
            <strong id="metric-users">-</strong>
          </article>
          <article class="metric">
            <span class="label">drive</span>
            <strong id="metric-drive">checking</strong>
          </article>
          <article class="metric">
            <span class="label">audit</span>
            <strong id="metric-audit">checking</strong>
          </article>
        </div>
        <div class="grid">
          <article class="panel">
            <div class="panel-head"><span>identity</span><span class="panel-meta">signed session</span></div>
            <div class="panel-body"><dl id="session-details"></dl></div>
          </article>
          <article class="panel">
            <div class="panel-head"><span>google drive</span><span class="panel-meta">source</span></div>
            <div class="panel-body">
              <p id="drive-status">Checking connection...</p>
              <div class="row">
                <button id="drive-connect" type="button" aria-describedby="drive-help">Connect Drive</button>
                <button id="drive-disconnect" class="ghost hidden" type="button">Disconnect</button>
              </div>
              <p id="drive-help" class="help">Connect the signed-in Google account with read-only Drive access.</p>
            </div>
          </article>
          <article class="panel">
            <div class="panel-head"><span>agent access</span><span class="panel-meta">mcp</span></div>
            <div class="panel-body"><p id="mcp-status">Connect Google Drive before enabling agent access.</p></div>
          </article>
          <article class="panel">
            <div class="panel-head"><span>audit log</span><span class="panel-meta">proof</span></div>
            <div class="panel-body"><p id="audit-status">Checking audit log...</p></div>
          </article>
        </div>
      </section>
      <p id="error" role="alert"></p>
    </main>
    <script src="/assets/app.js" type="module"></script>
  </body>
</html>`;

const loginFailedHtml = (message: string): string => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Pact login failed</title>
    <link rel="stylesheet" href="/assets/app.css">
  </head>
  <body>
    <main class="shell">
      <section class="panel">
        <h1>Login failed</h1>
        <p>${escapeHtml(message)}</p>
        <a class="button-link" href="/">Back to sign in</a>
      </section>
    </main>
  </body>
</html>`;

const APP_CSS = `
:root {
  color-scheme: dark;
  --bg: #0d0d0d;
  --panel: #161616;
  --panel-2: #1f1f1f;
  --line: rgba(255, 255, 255, 0.1);
  --line-strong: rgba(255, 255, 255, 0.16);
  --text: #fafafa;
  --muted: #a8a8a8;
  --faint: #737373;
  --accent: #fafafa;
  --accent-fg: #0d0d0d;
  --green: #9ab09a;
  --amber: #c0b080;
  --red: #d98585;
  font-family: Geist, -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
}
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle at 20% 10%, rgba(255, 255, 255, 0.05), transparent 28rem),
    var(--bg);
}
*, *::before, *::after {
  box-sizing: border-box;
}
button, input {
  font: inherit;
}
.shell {
  max-width: 1100px;
  margin: 0 auto;
  padding: 30px 20px 40px;
}
.topbar {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 24px;
}
.eyebrow {
  margin: 0 0 4px;
  color: var(--faint);
  font: 11px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-weight: 700;
  letter-spacing: 0;
  text-transform: uppercase;
}
h1, h2, p {
  margin-top: 0;
}
h1 {
  max-width: 13ch;
  margin-bottom: 10px;
  font-family: ui-serif, "New York", "Iowan Old Style", Palatino, Georgia, serif;
  font-size: clamp(34px, 6vw, 58px);
  font-weight: 400;
  line-height: 1.15;
}
h2 {
  margin-bottom: 10px;
  font-size: 24px;
  font-weight: 500;
}
.lede {
  max-width: 520px;
  color: var(--muted);
  font-size: 16px;
  line-height: 1.55;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 12px;
}
.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 12px;
}
.metric {
  min-height: 86px;
  padding: 14px;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
}
.metric strong {
  display: block;
  margin-top: 5px;
  overflow-wrap: anywhere;
  font-size: 20px;
  font-weight: 750;
}
.panel {
  overflow: hidden;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  box-shadow: 0 18px 60px rgba(0, 0, 0, 0.22);
}
.panel-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  border-bottom: 1px solid var(--line);
  background: var(--panel-2);
  color: var(--muted);
  font: 11px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  text-transform: uppercase;
}
.panel-meta {
  margin-left: auto;
  color: var(--faint);
}
.panel-body {
  padding: 18px;
}
.login-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(320px, 420px);
  gap: 24px;
  align-items: start;
}
#login-form {
  display: grid;
  gap: 12px;
}
#login-form label {
  margin-bottom: -4px;
}
#login-submit {
  margin-top: 2px;
}
.row {
  display: flex;
  gap: 8px;
  align-items: stretch;
}
.dots {
  display: inline-flex;
  gap: 5px;
}
.dots span {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: var(--faint);
  opacity: 0.65;
}
.label {
  color: var(--faint);
  font: 11px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  text-transform: uppercase;
}
label {
  display: block;
  margin-bottom: 8px;
  color: var(--muted);
  font: 11px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  text-transform: uppercase;
}
input {
  width: 100%;
  min-width: 0;
  border: 1px solid var(--line-strong);
  border-radius: 6px;
  padding: 10px;
  background: #101010;
  color: var(--text);
  font: 12px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
button, .button-link {
  border: 0;
  border-radius: 6px;
  padding: 10px 14px;
  background: var(--accent);
  color: var(--accent-fg);
  cursor: pointer;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 42px;
  min-width: 0;
  line-height: 1.2;
  overflow-wrap: anywhere;
  text-align: center;
  white-space: normal;
  font-weight: 650;
}
button:hover:not(:disabled), .button-link:hover {
  background: #ffffff;
}
button:disabled {
  cursor: not-allowed;
  background: #2a2a2a;
  color: var(--faint);
  border: 1px solid var(--line);
}
.ghost {
  background: transparent;
  color: var(--muted);
  border: 1px solid var(--line-strong);
}
.ghost:hover:not(:disabled) {
  background: var(--panel-2);
  color: var(--text);
}
button:focus-visible,
.button-link:focus-visible,
input:focus-visible {
  outline: 2px solid rgba(250, 250, 250, 0.42);
  outline-offset: 2px;
}
.hidden {
  display: none;
}
.help {
  margin: 8px 0 0;
  color: var(--faint);
  font-size: 12px;
}
.notice {
  padding: 10px 12px;
  border: 1px solid rgba(192, 176, 128, 0.36);
  border-radius: 8px;
  background: rgba(192, 176, 128, 0.08);
  color: #dfd3a2;
}
.workspace-summary {
  margin: 0;
  padding: 10px 12px;
  border: 1px solid var(--line-strong);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.045);
  color: var(--muted);
  font-size: 13px;
  line-height: 1.45;
}
.terminal-line {
  margin: 0;
  color: var(--muted);
  font: 12px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
dl {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 8px 12px;
  margin: 0;
}
dt {
  color: var(--faint);
  font: 11px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  text-transform: uppercase;
}
dd {
  margin: 0;
  min-width: 0;
  overflow-wrap: anywhere;
}
#error {
  margin-top: 16px;
  padding: 10px 12px;
  border: 1px solid rgba(217, 133, 133, 0.34);
  border-radius: 8px;
  background: rgba(217, 133, 133, 0.1);
  color: #f0b0b0;
  font-weight: 600;
}
#error:empty {
  display: none;
}
@media (max-width: 640px) {
  .shell {
    padding: 24px 14px;
  }
  .topbar, .row, .login-grid {
    align-items: stretch;
    flex-direction: column;
    display: flex;
  }
  .metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  button, .button-link {
    width: 100%;
  }
}
`;

const APP_JS = `
const $ = (id) => document.getElementById(id);
let csrfToken = "";
let refreshing = false;
let appConfig = { mode: "production", oauthConfigured: false, defaultWorkspaceId: null };

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const setError = (message = "") => {
  $("error").textContent = message;
};

const messageForError = (path, status, body) => {
  const code = body?.error;
  if (path.includes("/v1/auth/google/start")) {
    if (status === 400 || code === "invalid_workspace") return "Enter a valid workspace UUID.";
    if (status === 403 || code === "origin") return "This page was opened from an unexpected local address. Reload the dashboard and try again.";
    if (status === 503 || code === "misconfigured") return "Dashboard login is not configured for this environment.";
  }
  if (path.includes("/v1/connections/google-drive/start")) {
    if (status === 403 || code === "csrf") return "Refresh the page before connecting Drive.";
    if (status === 401) return "Sign in again before connecting Drive.";
    if (status === 503 || code === "misconfigured") return "Drive connection is not configured for this environment.";
  }
  if (status === 401) return "Your session expired. Sign in again.";
  if (status >= 500) return "A Pact service is unavailable. Try again in a moment.";
  return body?.message || code || path + " returned " + status;
};

const requestJson = async (path, init = {}) => {
  const devHeaders = appConfig.mode !== "production" ? { "x-pact-local-dev": "1" } : {};
  const res = await fetch(path, {
    ...init,
    headers: {
      accept: "application/json",
      ...devHeaders,
      ...(init.headers ?? {}),
    },
  });
  if (!res.ok) {
    let body = null;
    try {
      body = await res.json();
    } catch {}
    throw new Error(messageForError(path, res.status, body));
  }
  return res.json();
};

const showView = (name) => {
  for (const id of ["loading", "login", "dashboard"]) {
    $(id).classList.toggle("hidden", id !== name);
  }
  $("logout").classList.toggle("hidden", name !== "dashboard");
};

const refreshSession = async () => {
  if (refreshing || !csrfToken) return false;
  refreshing = true;
  try {
    const res = await fetch("/v1/session/refresh", {
      method: "POST",
      headers: { "x-pact-csrf": csrfToken },
    });
    return res.ok;
  } finally {
    refreshing = false;
  }
};

const loadConfig = async () => {
  try {
    appConfig = await requestJson("/v1/config");
  } catch {}
  const workspaceInput = $("workspace-id");
  const workspaceField = $("workspace-field");
  const workspaceSummary = $("workspace-summary");
  const defaultWorkspaceId = appConfig.defaultWorkspaceId;
  if (defaultWorkspaceId && uuidPattern.test(defaultWorkspaceId)) {
    workspaceInput.value = defaultWorkspaceId;
    workspaceField.classList.add("hidden");
    workspaceSummary.classList.remove("hidden");
    workspaceSummary.textContent = "Demo workspace selected. Continue with Google to sign in.";
  } else {
    const lastWorkspaceId = window.localStorage.getItem("pact:lastWorkspaceId") || "";
    if (!workspaceInput.value && uuidPattern.test(lastWorkspaceId)) {
      workspaceInput.value = lastWorkspaceId;
    }
    workspaceField.classList.remove("hidden");
    workspaceSummary.classList.add("hidden");
  }
  const oauthHelp = $("oauth-help");
  if (!appConfig.oauthConfigured) {
    oauthHelp.classList.remove("hidden");
    oauthHelp.textContent =
      "Google OAuth credentials are not configured for this dashboard environment.";
  } else {
    oauthHelp.classList.add("hidden");
  }
};

const renderSession = (session) => {
  $("metric-workspace").textContent = session.workspaceId ?? "-";
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
  $("metric-users").textContent = String(status.users?.count ?? 0);
  const driveStatus = drive?.status || "unknown";
  $("metric-drive").textContent = driveStatus === "not_configured" ? "not set" : driveStatus;
  $("metric-audit").textContent = status.audit?.head ? "active" : "no head";
  $("drive-status").textContent =
    driveStatus === "not_configured"
      ? "Drive is not connected yet."
      : driveStatus === "connected"
        ? "Drive connected for " + (drive.email || "this user") + "."
        : "Drive connection status: " + driveStatus;
  $("drive-connect").textContent = driveStatus === "connected" ? "Reconnect Drive" : "Connect Drive";
  $("drive-connect").disabled = false;
  const canDisconnect = !["not_configured", "unknown", "disconnected"].includes(driveStatus);
  $("drive-disconnect").classList.toggle("hidden", !canDisconnect);
  $("drive-disconnect").disabled = !canDisconnect;
  $("mcp-status").textContent =
    driveStatus === "connected"
      ? "Agent access can use this workspace once MCP credentials are issued."
      : "Connect Google Drive before enabling agent access.";
  $("audit-status").textContent = status.audit?.head
    ? "Audit log is receiving signed events."
    : "No audit log checkpoint found yet.";
};

const renderStatusUnavailable = (message) => {
  $("metric-users").textContent = "-";
  $("metric-drive").textContent = "unavailable";
  $("metric-audit").textContent = "unavailable";
  $("drive-status").textContent = "Connection status is unavailable.";
  $("drive-connect").disabled = false;
  $("drive-disconnect").classList.add("hidden");
  $("drive-disconnect").disabled = true;
  $("mcp-status").textContent = "Agent access status is unavailable.";
  $("audit-status").textContent = message || "Audit log status is unavailable.";
};

const load = async () => {
  setError();
  await loadConfig();
  showView("loading");
  const session = await requestJson("/v1/session");
  if (!session.authenticated) {
    showView("login");
    return;
  }
  showView("dashboard");
  csrfToken = session.csrfToken ?? "";
  renderSession(session);
  try {
    renderStatus(await requestJson("/v1/workspace/status"));
  } catch (error) {
    if (await refreshSession()) {
      renderStatus(await requestJson("/v1/workspace/status"));
      return;
    }
    const message = error instanceof Error ? error.message : "Workspace status failed";
    renderStatusUnavailable(message);
    setError(message);
  }
};

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setError();
  const form = event.currentTarget;
  const workspaceId = String(new FormData(form).get("workspaceId") ?? "").trim();
  if (!uuidPattern.test(workspaceId)) {
    setError("Enter a valid workspace UUID.");
    $("workspace-id").focus();
    return;
  }
  window.localStorage.setItem("pact:lastWorkspaceId", workspaceId);
  const input = $("workspace-id");
  const button = $("login-submit");
  input.disabled = true;
  button.disabled = true;
  button.textContent = "Redirecting to Google...";
  try {
    const body = await requestJson("/v1/auth/google/start", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ workspaceId }),
    });
    window.location.href = body.location;
  } catch (error) {
    input.disabled = false;
    button.disabled = false;
    button.textContent = "Continue with Google";
    setError(error instanceof Error ? error.message : "Login failed");
  }
});

$("logout").addEventListener("click", async () => {
  await fetch("/v1/session", { method: "DELETE", headers: { "x-pact-csrf": csrfToken } });
  await load();
});

$("drive-connect").addEventListener("click", async () => {
  setError();
  const button = $("drive-connect");
  button.disabled = true;
  const previous = button.textContent;
  button.textContent = "Redirecting to Google...";
  try {
    const body = await requestJson("/v1/connections/google-drive/start", {
      method: "POST",
      headers: { "x-pact-csrf": csrfToken },
    });
    window.location.href = body.location;
  } catch (error) {
    button.disabled = false;
    button.textContent = previous || "Connect Drive";
    setError(error instanceof Error ? error.message : "Drive connection failed");
  }
});

$("drive-disconnect").addEventListener("click", async () => {
  setError();
  const button = $("drive-disconnect");
  button.disabled = true;
  try {
    await requestJson("/v1/connections/google-drive", {
      method: "DELETE",
      headers: { "x-pact-csrf": csrfToken },
    });
    await load();
  } catch (error) {
    button.disabled = false;
    setError(error instanceof Error ? error.message : "Drive disconnect failed");
  }
});

load().catch((error) => {
  showView("login");
  setError(error instanceof Error ? error.message : "Dashboard failed");
});
`;

export default app;
