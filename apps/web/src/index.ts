import { isUuid, timingSafeEqualString } from "@getpact/core";
import {
  type AnalyticsEngineDataset,
  type MetricsClient,
  metricsFromEnv,
  type SentryClient,
  sentryFromEnv,
} from "@getpact/logger";
import { type Context, Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { decodeProtectedHeader, importJWK, type JWK, jwtVerify } from "jose";
import { APP_CSS, APP_JS, INDEX_HTML } from "./generated-assets.js";

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
  MCP_SERVER_BASE_URL?: string;
  GOOGLE_OAUTH_CLIENT_ID: string;
  GOOGLE_OAUTH_AUTHORIZATION_ENDPOINT?: string;
  WEB_ISSUER_SERVICE_TOKEN: string;
  SENTRY_DSN?: string;
  SENTRY_ENVIRONMENT?: string;
  SENTRY_RELEASE?: string;
  METRICS?: AnalyticsEngineDataset;
};

type AppVariables = {
  sentry: SentryClient;
  metrics: MetricsClient;
};

type AppContext = Context<{ Bindings: Env; Variables: AppVariables }>;

const ADMIN_ACCESS_COOKIE = "__Host-pact-admin-access";
const ADMIN_REFRESH_COOKIE = "__Host-pact-admin-refresh";
const AUDIT_ACCESS_COOKIE = "__Host-pact-audit-access";
const AUDIT_REFRESH_COOKIE = "__Host-pact-audit-refresh";
const MCP_ACCESS_COOKIE = "__Host-pact-mcp-access";
const MCP_REFRESH_COOKIE = "__Host-pact-mcp-refresh";
const WORKSPACE_COOKIE = "__Host-pact-workspace";
const CSRF_COOKIE = "__Host-pact-csrf";
const OAUTH_STATE_COOKIE = "__Host-pact-oauth-state";
const OAUTH_VERIFIER_COOKIE = "__Host-pact-oauth-verifier";
const OAUTH_WORKSPACE_COOKIE = "__Host-pact-oauth-workspace";
const DRIVE_STATE_COOKIE = "__Host-pact-drive-state";
const DRIVE_VERIFIER_COOKIE = "__Host-pact-drive-verifier";
const DRIVE_WORKSPACE_COOKIE = "__Host-pact-drive-workspace";
const DRIVE_NONCE_COOKIE = "__Host-pact-drive-nonce";
const DRIVE_ADMIN_ACCESS_COOKIE = "__Host-pact-drive-admin-access";

const GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const ADMIN_AUDIENCE = "pact-admin";
const AUDIT_AUDIENCE = "pact-audit";
const MCP_AUDIENCE = "pact-mcp";
const TEN_MINUTES = 600;
const THIRTY_DAYS = 30 * 24 * 60 * 60;
const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
const JWKS_KID_MISS_TTL_MS = 30 * 1000;

const app = new Hono<{ Bindings: Env; Variables: AppVariables }>();

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
  const sentry = sentryFromEnv(c.env, "web");
  const metrics = metricsFromEnv(c.env, "web");
  c.set("sentry", sentry);
  c.set("metrics", metrics);
  applyDashboardHeaders(c);
  try {
    await next();
  } catch (err) {
    sentry.captureRequest(c.req.raw, err);
    throw err;
  }
  applyDashboardHeaders(c);
});
app.use("/v1/*", bodyLimit({ maxSize: 8 * 1024 }));

app.onError((err, c) => {
  console.error(err);
  const sentry = c.get("sentry");
  sentry?.captureRequest(c.req.raw, err);
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

const driveCallbackCookiePath = (env: Env): string => {
  try {
    return new URL(driveCallbackUrl(env)).pathname || "/";
  } catch {
    return "/";
  }
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

const refreshPactToken = async (
  env: Env,
  workspaceId: string,
  refreshToken: string,
  audience: string,
): Promise<TokenResponse | null> => {
  const res = await fetchWithTimeout(urlFor(env.ISSUER_BASE_URL, "/v1/refresh"), {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      workspaceId,
      refreshToken,
      audience,
    }),
  });
  if (!res.ok) return null;
  return (await res.json()) as TokenResponse;
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

const clearCookie = (name: string, env: Env, opts: { path?: string } = {}): string =>
  cookie(name, "", {
    env,
    maxAge: 0,
    httpOnly: true,
    ...(opts.path ? { path: opts.path } : {}),
  });

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
  body: { admin: TokenResponse; audit: TokenResponse; mcp?: TokenResponse },
  csrfToken = randomBase64Url(24),
): void => {
  const now = Math.floor(Date.now() / 1000);
  const accessMaxAgeFor = (token: TokenResponse): number => Math.max(token.exp - now, 1);
  const refreshMaxAgeFor = (token: TokenResponse): number => {
    if (!token.refreshExpiresAt) {
      return THIRTY_DAYS;
    }
    const exp = Math.floor(Date.parse(token.refreshExpiresAt) / 1000);
    return Number.isFinite(exp) ? Math.max(exp - now, 1) : THIRTY_DAYS;
  };
  appendCookie(
    c,
    cookie(ADMIN_ACCESS_COOKIE, body.admin.token, {
      env: c.env,
      httpOnly: true,
      maxAge: accessMaxAgeFor(body.admin),
    }),
  );
  appendCookie(
    c,
    cookie(ADMIN_REFRESH_COOKIE, body.admin.refreshToken, {
      env: c.env,
      httpOnly: true,
      maxAge: refreshMaxAgeFor(body.admin),
    }),
  );
  appendCookie(
    c,
    cookie(AUDIT_ACCESS_COOKIE, body.audit.token, {
      env: c.env,
      httpOnly: true,
      maxAge: accessMaxAgeFor(body.audit),
    }),
  );
  appendCookie(
    c,
    cookie(AUDIT_REFRESH_COOKIE, body.audit.refreshToken, {
      env: c.env,
      httpOnly: true,
      maxAge: refreshMaxAgeFor(body.audit),
    }),
  );
  if (body.mcp) {
    appendCookie(
      c,
      cookie(MCP_ACCESS_COOKIE, body.mcp.token, {
        env: c.env,
        httpOnly: true,
        maxAge: accessMaxAgeFor(body.mcp),
      }),
    );
    appendCookie(
      c,
      cookie(MCP_REFRESH_COOKIE, body.mcp.refreshToken, {
        env: c.env,
        httpOnly: true,
        maxAge: refreshMaxAgeFor(body.mcp),
      }),
    );
  }
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
    MCP_ACCESS_COOKIE,
    MCP_REFRESH_COOKIE,
    WORKSPACE_COOKIE,
    CSRF_COOKIE,
    OAUTH_STATE_COOKIE,
    OAUTH_VERIFIER_COOKIE,
    OAUTH_WORKSPACE_COOKIE,
    DRIVE_STATE_COOKIE,
    DRIVE_VERIFIER_COOKIE,
    DRIVE_WORKSPACE_COOKIE,
    DRIVE_NONCE_COOKIE,
    DRIVE_ADMIN_ACCESS_COOKIE,
  ]) {
    appendCookie(c, clearCookie(name, c.env));
  }
  appendCookie(
    c,
    clearCookie("__Secure-pact-drive-admin-access", c.env, {
      path: driveCallbackCookiePath(c.env),
    }),
  );
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
    DRIVE_ADMIN_ACCESS_COOKIE,
  ]) {
    appendCookie(c, clearCookie(name, c.env));
  }
  appendCookie(
    c,
    clearCookie("__Secure-pact-drive-admin-access", c.env, {
      path: driveCallbackCookiePath(c.env),
    }),
  );
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

const mcpEndpoint = (env: Env, workspaceId: string): string | null =>
  env.MCP_SERVER_BASE_URL ? `${baseUrl(env.MCP_SERVER_BASE_URL)}/${workspaceId}/mcp` : null;

type McpPayload = {
  jsonrpc?: unknown;
  id?: unknown;
  result?: unknown;
  error?: { code?: unknown; message?: unknown };
};

type McpToolCall = {
  endpoint: string;
  payload: McpPayload;
};

const mcpResponseCookieMaxAge = (token: TokenResponse): number => {
  const now = Math.floor(Date.now() / 1000);
  return Math.max(token.exp - now, 1);
};

const mcpRefreshCookieMaxAge = (token: TokenResponse): number => {
  const refreshExp = token.refreshExpiresAt
    ? Math.floor(Date.parse(token.refreshExpiresAt) / 1000)
    : null;
  return refreshExp && Number.isFinite(refreshExp)
    ? Math.max(refreshExp - Math.floor(Date.now() / 1000), 1)
    : THIRTY_DAYS;
};

const sanitizeMcpPayload = (body: unknown): McpPayload => {
  const payload = body as McpPayload;
  const sanitized: McpPayload = {
    jsonrpc: payload.jsonrpc === "2.0" ? "2.0" : undefined,
    id: typeof payload.id === "string" || typeof payload.id === "number" ? payload.id : undefined,
  };
  if (payload.error) {
    sanitized.error = {
      code: typeof payload.error.code === "number" ? payload.error.code : undefined,
      message: typeof payload.error.message === "string" ? payload.error.message : "MCP error",
    };
  } else {
    sanitized.result = payload.result ?? null;
  }
  return sanitized;
};

const callMcpTool = async (
  c: AppContext,
  input: { name: string; arguments?: Record<string, unknown>; id?: string | number },
): Promise<
  | { ok: true; value: McpToolCall }
  | { ok: false; body: Record<string, unknown>; status: 401 | 502 | 503 }
> => {
  const cookies = sessionCookies(c);
  let token = cookies[MCP_ACCESS_COOKIE];
  const workspaceId = cookies[WORKSPACE_COOKIE];
  if (!token || !workspaceId || !isUuid(workspaceId)) {
    return { ok: false, body: { error: "not_authenticated" }, status: 401 };
  }
  const endpoint = mcpEndpoint(c.env, workspaceId);
  if (!endpoint) {
    return {
      ok: false,
      body: { error: "misconfigured", message: "MCP server URL is not configured" },
      status: 503,
    };
  }
  const requestMcp = () =>
    bearerFetch(endpoint, token as string, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: input.id ?? 1,
        method: "tools/call",
        params: { name: input.name, arguments: input.arguments ?? {} },
      }),
    });

  let response = await requestMcp();
  if (response.status === 401 && cookies[MCP_REFRESH_COOKIE]) {
    const refreshed = await refreshPactToken(
      c.env,
      workspaceId,
      cookies[MCP_REFRESH_COOKIE],
      MCP_AUDIENCE,
    );
    if (refreshed) {
      token = refreshed.token;
      appendCookie(
        c,
        cookie(MCP_ACCESS_COOKIE, refreshed.token, {
          env: c.env,
          httpOnly: true,
          maxAge: mcpResponseCookieMaxAge(refreshed),
        }),
      );
      appendCookie(
        c,
        cookie(MCP_REFRESH_COOKIE, refreshed.refreshToken, {
          env: c.env,
          httpOnly: true,
          maxAge: mcpRefreshCookieMaxAge(refreshed),
        }),
      );
      response = await requestMcp();
    }
  }

  const body = (await response.json().catch(() => ({}))) as unknown;
  if (response.status === 401) {
    return { ok: false, body: { error: "not_authenticated" }, status: 401 };
  }
  if (!response.ok) {
    return { ok: false, body: { error: "mcp_unavailable", status: response.status }, status: 502 };
  }
  return { ok: true, value: { endpoint, payload: sanitizeMcpPayload(body) } };
};

const mcpToolText = (
  payload: McpPayload,
): { ok: true; text: string } | { ok: false; message: string } => {
  if (payload.error) {
    return {
      ok: false,
      message:
        typeof payload.error.message === "string" ? payload.error.message : "MCP tool call failed",
    };
  }
  const result = payload.result as {
    content?: Array<{ type?: unknown; text?: unknown }>;
    isError?: unknown;
  } | null;
  const text = result?.content?.find(
    (item) => item.type === "text" && typeof item.text === "string",
  )?.text as string | undefined;
  if (!text) return { ok: false, message: "MCP tool returned no text content" };
  if (result?.isError) return { ok: false, message: text };
  return { ok: true, text };
};

const mcpToolJson = <T>(
  payload: McpPayload,
): { ok: true; value: T } | { ok: false; message: string } => {
  const text = mcpToolText(payload);
  if (!text.ok) return text;
  try {
    return { ok: true, value: JSON.parse(text.text) as T };
  } catch {
    return { ok: false, message: "MCP tool returned malformed JSON" };
  }
};

const stringValue = (value: unknown, max = 500): string | undefined =>
  typeof value === "string"
    ? [...value]
        .map((char) => {
          const code = char.charCodeAt(0);
          return code < 32 || code === 127 ? " " : char;
        })
        .join("")
        .slice(0, max)
    : undefined;

const isSafeDriveFileId = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9_-]{1,256}$/.test(value);

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

  clearDriveOAuthAttempt(c);
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
  const url = new URL(c.req.url);
  const state = url.searchParams.get("state") ?? "";
  if (
    state &&
    callbackCookies[DRIVE_STATE_COOKIE] &&
    timingSafeEqualString(state, callbackCookies[DRIVE_STATE_COOKIE])
  ) {
    return handleDriveCallback(c);
  }
  if (!webBaseUrl(c.env)) {
    return c.json({ error: "misconfigured", message: "WEB_BASE_URL is required" }, 503);
  }
  const code = url.searchParams.get("code") ?? "";
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
        audiences: [ADMIN_AUDIENCE, AUDIT_AUDIENCE, MCP_AUDIENCE],
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
  const mcp = body.tokens[MCP_AUDIENCE];
  if (!admin || !audit) {
    clearOAuthAttempt(c);
    return c.html(loginFailedHtml("The issuer returned an incomplete dashboard session."), 502);
  }
  if (!mcp) {
    clearOAuthAttempt(c);
    return c.html(
      loginFailedHtml(
        "The issuer did not return MCP credentials. Update the issuer to allow the pact-mcp dashboard audience, then sign in again.",
      ),
      502,
    );
  }
  storeSession(c, workspaceId, { admin, audit, mcp });
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

  clearOAuthAttempt(c);
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
  appendCookie(
    c,
    cookie(DRIVE_ADMIN_ACCESS_COOKIE, adminToken, {
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
  const adminToken = cookies[ADMIN_ACCESS_COOKIE] ?? cookies[DRIVE_ADMIN_ACCESS_COOKIE];
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
    const body = await response
      ?.json<{ error?: string; message?: string }>()
      .catch((): { error?: string; message?: string } => ({}));
    const message = body?.message ?? "Google Drive could not be connected for this workspace user.";
    return c.html(
      loginFailedHtml(message),
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
  const mcpRefreshToken = cookies[MCP_REFRESH_COOKIE];
  const workspaceId = cookies[WORKSPACE_COOKIE];
  if (!adminRefreshToken || !auditRefreshToken || !workspaceId) {
    return c.json({ error: "not_authenticated" }, 401);
  }
  const [adminRes, auditRes] = await Promise.all([
    refreshPactToken(c.env, workspaceId, adminRefreshToken, ADMIN_AUDIENCE),
    refreshPactToken(c.env, workspaceId, auditRefreshToken, AUDIT_AUDIENCE),
  ]);
  if (!adminRes || !auditRes) {
    clearSession(c);
    return c.json({ error: "not_authenticated" }, 401);
  }
  let mcp: TokenResponse | undefined;
  if (mcpRefreshToken) {
    mcp = (await refreshPactToken(c.env, workspaceId, mcpRefreshToken, MCP_AUDIENCE)) ?? undefined;
  }
  storeSession(
    c,
    workspaceId,
    { admin: adminRes, audit: auditRes, ...(mcp ? { mcp } : {}) },
    cookies[CSRF_COOKIE],
  );
  if (mcpRefreshToken && !mcp) {
    appendCookie(c, clearCookie(MCP_ACCESS_COOKIE, c.env));
    appendCookie(c, clearCookie(MCP_REFRESH_COOKIE, c.env));
  }
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
    mcp: {
      configured: !!mcpEndpoint(c.env, workspaceId),
      endpoint: mcpEndpoint(c.env, workspaceId),
      audience: MCP_AUDIENCE,
    },
  });
});

app.post("/v1/drive/files", async (c) => {
  if (!requireCsrf(c)) return c.json({ error: "csrf" }, 403);
  const body = await c.req
    .json<{ pageToken?: unknown; pageSize?: unknown }>()
    .catch((): { pageToken?: unknown; pageSize?: unknown } => ({}));
  const pageSize =
    typeof body.pageSize === "number" && Number.isFinite(body.pageSize)
      ? Math.max(1, Math.min(20, Math.floor(body.pageSize)))
      : 10;
  const args: Record<string, unknown> = { pageSize };
  const pageToken = stringValue(body.pageToken, 500);
  if (pageToken) args.pageToken = pageToken;

  const called = await callMcpTool(c, {
    id: "drive-files",
    name: "pact.drive.files.list",
    arguments: args,
  });
  if (!called.ok) return c.json(called.body, called.status);

  const parsed = mcpToolJson<{
    files?: Array<Record<string, unknown>>;
    nextPageToken?: unknown;
  }>(called.value.payload);
  if (!parsed.ok) return c.json({ error: "drive_files_failed", message: parsed.message }, 502);
  const files = Array.isArray(parsed.value.files)
    ? parsed.value.files
        .map((file) => ({
          id: stringValue(file.id, 256),
          name: stringValue(file.name, 300),
          mimeType: stringValue(file.mimeType, 200),
          modifiedTime: stringValue(file.modifiedTime, 80),
          size: stringValue(file.size, 40),
        }))
        .filter((file) => isSafeDriveFileId(file.id))
    : [];

  return c.json({ files });
});

app.post("/v1/drive/index", async (c) => {
  if (!requireCsrf(c)) return c.json({ error: "csrf" }, 403);
  const body = await c.req
    .json<{ fileId?: unknown; fileName?: unknown; modifiedTime?: unknown }>()
    .catch((): { fileId?: unknown; fileName?: unknown; modifiedTime?: unknown } => ({}));
  if (!isSafeDriveFileId(body.fileId)) {
    return c.json({ error: "invalid_file", message: "Choose a valid Drive file." }, 400);
  }
  const args: Record<string, unknown> = {
    fileId: body.fileId,
    mimeType: "text/plain",
  };
  const fileName = stringValue(body.fileName, 300);
  const modifiedTime = stringValue(body.modifiedTime, 80);
  if (fileName) args.fileName = fileName;
  if (modifiedTime) args.modifiedTime = modifiedTime;

  const called = await callMcpTool(c, {
    id: "drive-index",
    name: "pact.drive.file.index",
    arguments: args,
  });
  if (!called.ok) return c.json(called.body, called.status);

  const parsed = mcpToolJson<{
    fileId?: unknown;
    fileName?: unknown;
    chunks?: unknown;
    indexedChars?: unknown;
    truncated?: unknown;
  }>(called.value.payload);
  if (!parsed.ok) return c.json({ error: "drive_index_failed", message: parsed.message }, 502);
  return c.json({
    fileId: stringValue(parsed.value.fileId, 256) ?? body.fileId,
    fileName: stringValue(parsed.value.fileName, 300) ?? fileName ?? null,
    chunks: typeof parsed.value.chunks === "number" ? parsed.value.chunks : 0,
    indexedChars: typeof parsed.value.indexedChars === "number" ? parsed.value.indexedChars : 0,
    truncated: parsed.value.truncated === true,
  });
});

app.post("/v1/drive/search", async (c) => {
  if (!requireCsrf(c)) return c.json({ error: "csrf" }, 403);
  const body = await c.req
    .json<{ query?: unknown; limit?: unknown }>()
    .catch((): { query?: unknown; limit?: unknown } => ({}));
  const query = stringValue(body.query, 200)?.trim().replace(/\s+/g, " ");
  if (!query) {
    return c.json({ error: "invalid_query", message: "Enter a search query." }, 400);
  }
  const limit =
    typeof body.limit === "number" && Number.isFinite(body.limit)
      ? Math.max(1, Math.min(10, Math.floor(body.limit)))
      : 5;
  const called = await callMcpTool(c, {
    id: "drive-search",
    name: "pact.drive.search",
    arguments: { query, limit },
  });
  if (!called.ok) return c.json(called.body, called.status);

  const parsed = mcpToolJson<{
    query?: unknown;
    results?: Array<Record<string, unknown>>;
  }>(called.value.payload);
  if (!parsed.ok) return c.json({ error: "drive_search_failed", message: parsed.message }, 502);
  const results = Array.isArray(parsed.value.results)
    ? parsed.value.results
        .map((item) => ({
          fileId: stringValue(item.fileId, 256),
          fileName: stringValue(item.fileName, 300),
          mimeType: stringValue(item.mimeType, 200),
          chunkIndex: typeof item.chunkIndex === "number" ? item.chunkIndex : null,
          snippet: stringValue(item.snippet, 700) ?? "",
          indexedAt: stringValue(item.indexedAt, 80),
        }))
        .filter((item) => isSafeDriveFileId(item.fileId))
    : [];
  return c.json({ query, results });
});

app.post("/v1/mcp/test", async (c) => {
  if (!requireCsrf(c)) return c.json({ error: "csrf" }, 403);
  const called = await callMcpTool(c, {
    id: 1,
    name: "pact.whoami",
    arguments: {},
  });
  if (!called.ok) return c.json(called.body, called.status);
  return c.json({ endpoint: called.value.endpoint, response: called.value.payload });
});

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

export default app;
