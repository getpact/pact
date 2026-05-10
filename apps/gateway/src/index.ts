import {
  assertAllowedUpstreamHost,
  assertSafeUpstreamUrl,
  isUuid,
  securityHeaders,
} from "@getpact/core";
import { createClient, schema, withWorkspace } from "@getpact/db";
import { createLogger, requestLogger } from "@getpact/logger";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { decodeJwt } from "jose";
import { emitGatewayAudit } from "./audit.js";
import { databaseRateLimiter } from "./rate-limit.js";

type Env = {
  DATABASE_URL: string;
  VERIFIER_URL: string;
  MEK?: string;
  ENVIRONMENT?: string;
  GATEWAY_AUDIENCE?: string;
  GATEWAY_UPSTREAM_TIMEOUT_MS?: string;
  GATEWAY_RATE_LIMIT?: string;
  GATEWAY_RATE_WINDOW_SECONDS?: string;
  GATEWAY_AUDIT_MODE?: string;
  UPSTREAM_HOST_ALLOWLIST?: string;
};

const app = new Hono<{ Bindings: Env }>();
const maxBodyBytes = 1024 * 1024;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 5000;
const MAX_UPSTREAM_TIMEOUT_MS = 30000;

const upstreamTimeout = (env: Env): number => {
  const raw = env.GATEWAY_UPSTREAM_TIMEOUT_MS;
  if (!raw) return DEFAULT_UPSTREAM_TIMEOUT_MS;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_UPSTREAM_TIMEOUT_MS;
  return Math.min(parsed, MAX_UPSTREAM_TIMEOUT_MS);
};

const DEFAULT_RATE_LIMIT = 60;
const DEFAULT_RATE_WINDOW_SECONDS = 60;

const parsePositiveInt = (raw: string | undefined, fallback: number, max: number): number => {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, max);
};

const gatewayAuditRequired = (env: Env): boolean =>
  env.GATEWAY_AUDIT_MODE === "required" ||
  (env.ENVIRONMENT === "production" && env.GATEWAY_AUDIT_MODE !== "best_effort");

const logger = createLogger({ base: { app: "gateway" } });

type VerifyOutput = {
  allow: boolean;
  reasons: string[];
};

export const buildGatewayTarget = (
  baseUrl: string,
  path: string,
  search: string,
  allowlist?: string,
  requireAllowlist = false,
): URL => {
  const target = assertSafeUpstreamUrl(baseUrl);
  assertAllowedUpstreamHost(target, allowlist, { required: requireAllowlist });
  const basePath = target.pathname.endsWith("/") ? target.pathname : `${target.pathname}/`;
  const cleanPath = path.replace(/^\/+/, "");
  for (const segment of cleanPath.split("/")) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      throw new Error("gateway path contains invalid encoding");
    }
    if (decoded === "." || decoded === "..") {
      throw new Error("gateway path escapes upstream base");
    }
    if (decoded.includes("/") || decoded.includes("\\")) {
      throw new Error("gateway path escapes upstream base");
    }
  }
  target.pathname = `${basePath}${cleanPath}`;
  if (!target.pathname.startsWith(basePath)) {
    throw new Error("gateway path escapes upstream base");
  }
  target.search = search;
  return target;
};

export const gatewayAuthorization = (
  method: string,
  brain: string,
  path: string,
): { action: string; resource: string } => ({
  action: `gateway.${method.toLowerCase()}`,
  resource: `gateway:${brain}:/${path.replace(/^\/+/, "")}`,
});

const bearerToken = (value: string | undefined): string | null => {
  if (!value?.startsWith("Bearer ")) return null;
  const token = value.slice("Bearer ".length).trim();
  return token.length > 0 ? token : null;
};

const verify = async (
  verifierUrl: string,
  input: { token: string; action: string; resource: string; audience: string },
): Promise<VerifyOutput> => {
  try {
    const res = await fetch(`${verifierUrl.replace(/\/+$/, "")}/v1/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = (await res.json()) as Partial<VerifyOutput>;
    if (typeof body.allow === "boolean" && Array.isArray(body.reasons)) {
      return { allow: body.allow, reasons: body.reasons };
    }
    return { allow: false, reasons: [`verifier returned ${res.status}`] };
  } catch {
    return { allow: false, reasons: ["verifier unavailable"] };
  }
};

export const forwardedRequestHeaders = (headers: Headers): Headers => {
  const out = new Headers();
  const blocked = new Set([
    "authorization",
    "cf-connecting-ip",
    "cf-ipcountry",
    "cf-ray",
    "connection",
    "content-length",
    "cookie",
    "forwarded",
    "host",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "x-api-key",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-http-method",
    "x-http-method-override",
    "x-method-override",
    "x-real-ip",
  ]);
  headers.forEach((value, key) => {
    if (!blocked.has(key.toLowerCase())) out.set(key, value);
  });
  return out;
};

const forwardedResponseHeaders = (headers: Headers): Headers => {
  const out = new Headers();
  const blocked = new Set([
    "connection",
    "content-length",
    "proxy-authenticate",
    "set-cookie",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
  ]);
  headers.forEach((value, key) => {
    if (!blocked.has(key.toLowerCase())) out.set(key, value);
  });
  return out;
};

app.use("*", requestLogger(logger, "gateway"));
app.use("*", async (c, next) => {
  await next();
  const headers = securityHeaders({ production: c.env.ENVIRONMENT === "production" });
  for (const [k, v] of Object.entries(headers)) c.header(k, v);
});
app.use("/:workspace/gateway/:brain/*", bodyLimit({ maxSize: maxBodyBytes }));

app.get("/health", (c) => c.json({ ok: true }));

app.all("/:workspace/gateway/:brain/*", async (c) => {
  const token = bearerToken(c.req.header("Authorization"));
  if (!token) {
    return c.json({ error: "unauthorized", message: "missing bearer token" }, 401);
  }

  const workspaceParam = c.req.param("workspace");
  const brainKind = c.req.param("brain");
  const path = c.req.param("*") ?? "";
  const audience = c.env.GATEWAY_AUDIENCE ?? "pact-gateway";
  const authz = gatewayAuthorization(c.req.method, brainKind, path);

  const verdict = await verify(c.env.VERIFIER_URL, {
    token,
    action: authz.action,
    resource: authz.resource,
    audience,
  });
  if (!verdict.allow) {
    return c.json({ error: "denied", reasons: verdict.reasons }, 403);
  }

  const claims = decodeJwt(token);
  const workspaceId = claims.org as string | undefined;
  if (!workspaceId || !isUuid(workspaceId)) {
    return c.json({ error: "unauthorized", message: "missing workspace claim" }, 401);
  }

  const db = createClient(c.env.DATABASE_URL);
  const [workspace] = await db
    .select({ id: schema.workspaces.id, slug: schema.workspaces.slug })
    .from(schema.workspaces)
    .where(
      isUuid(workspaceParam)
        ? eq(schema.workspaces.id, workspaceParam)
        : eq(schema.workspaces.slug, workspaceParam),
    )
    .limit(1);
  if (!workspace || workspace.id !== workspaceId) {
    return c.json({ error: "unauthorized", message: "workspace mismatch" }, 401);
  }
  const auditTarget = {
    resource: authz.resource,
    brain: brainKind,
    path: `/${path.replace(/^\/+/, "")}`,
    method: c.req.method,
  };
  const audit = async (input: {
    decision: "allow" | "deny";
    outcome: string;
    upstreamStatus?: number;
    reasons?: string[];
  }) => {
    const result = await emitGatewayAudit({
      db,
      mek: c.env.MEK,
      workspaceId,
      actorId: typeof claims.sub === "string" ? claims.sub : undefined,
      action: authz.action,
      decision: input.decision,
      target: auditTarget,
      supporting: {
        outcome: input.outcome,
        verifierReasons: verdict.reasons,
        ...(input.reasons ? { reasons: input.reasons } : {}),
        ...(input.upstreamStatus !== undefined ? { upstreamStatus: input.upstreamStatus } : {}),
      },
    });
    return result.ok || !gatewayAuditRequired(c.env) ? { ok: true as const } : result;
  };
  const auditFailure = (result: Awaited<ReturnType<typeof audit>>): Response | null =>
    result.ok
      ? null
      : c.json({ error: "audit_unavailable", message: "gateway audit is required" }, 503);

  const [brain] = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .select({
        baseUrl: schema.brains.baseUrl,
        authScheme: schema.brains.authScheme,
      })
      .from(schema.brains)
      .where(
        and(
          eq(schema.brains.workspaceId, workspaceId),
          eq(schema.brains.kind, brainKind),
          eq(schema.brains.status, "active"),
        ),
      )
      .limit(1),
  );
  if (!brain) {
    const failed = auditFailure(await audit({ decision: "deny", outcome: "brain_not_found" }));
    if (failed) return failed;
    return c.json({ error: "not_found", message: "brain not found" }, 404);
  }
  if (brain.authScheme !== "none") {
    const failed = auditFailure(
      await audit({ decision: "deny", outcome: "unsupported_auth_scheme" }),
    );
    if (failed) return failed;
    return c.json(
      { error: "not_implemented", message: "gateway brain auth is not implemented" },
      501,
    );
  }

  if (c.env.ENVIRONMENT !== "test") {
    const limit = parsePositiveInt(c.env.GATEWAY_RATE_LIMIT, DEFAULT_RATE_LIMIT, 1000);
    const windowSeconds = parsePositiveInt(
      c.env.GATEWAY_RATE_WINDOW_SECONDS,
      DEFAULT_RATE_WINDOW_SECONDS,
      3600,
    );
    const rateLimiter = databaseRateLimiter(c.env.DATABASE_URL);
    const verdictRate = await rateLimiter.hit(
      `gateway:${workspaceId}:${brainKind}`,
      limit,
      windowSeconds,
    );
    c.header("x-ratelimit-limit", String(limit));
    c.header("x-ratelimit-remaining", String(verdictRate.remaining));
    c.header("x-ratelimit-reset", String(Math.ceil(verdictRate.resetAt / 1000)));
    if (!verdictRate.allowed) {
      const failed = auditFailure(await audit({ decision: "deny", outcome: "rate_limited" }));
      if (failed) return failed;
      const retry = Math.max(1, Math.ceil((verdictRate.resetAt - Date.now()) / 1000));
      c.header("retry-after", String(retry));
      return c.json({ error: "rate_limited", message: "too many requests" }, 429);
    }
  }

  let target: URL;
  try {
    const requestUrl = new URL(c.req.url);
    target = buildGatewayTarget(
      brain.baseUrl,
      path,
      requestUrl.search,
      c.env.UPSTREAM_HOST_ALLOWLIST,
      c.env.ENVIRONMENT === "production",
    );
  } catch (e) {
    const message = e instanceof Error ? e.message : "invalid gateway upstream";
    const failed = auditFailure(
      await audit({ decision: "deny", outcome: "invalid_upstream", reasons: [message] }),
    );
    if (failed) return failed;
    return c.json({ error: "invalid_gateway_upstream", message }, 400);
  }

  const controller = new AbortController();
  const timeoutMs = upstreamTimeout(c.env);
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const init: RequestInit = {
    method: c.req.method,
    headers: forwardedRequestHeaders(c.req.raw.headers),
    redirect: "manual",
    signal: controller.signal,
  };
  if (c.req.method !== "GET" && c.req.method !== "HEAD") {
    init.body = c.req.raw.body;
  }
  let upstream: Response;
  try {
    upstream = await fetch(target, init);
  } catch (err) {
    clearTimeout(timer);
    const aborted =
      controller.signal.aborted || (err instanceof Error && err.name === "AbortError");
    const failed = auditFailure(
      await audit({ decision: "deny", outcome: aborted ? "timeout" : "upstream_failed" }),
    );
    if (failed) return failed;
    return aborted
      ? c.json({ error: "gateway_timeout", message: "upstream request timed out" }, 504)
      : c.json({ error: "bad_gateway", message: "upstream request failed" }, 502);
  }
  clearTimeout(timer);
  if (upstream.status >= 300 && upstream.status < 400) {
    const failed = auditFailure(
      await audit({ decision: "deny", outcome: "redirect", upstreamStatus: upstream.status }),
    );
    if (failed) return failed;
    return c.json({ error: "bad_gateway", message: "upstream returned redirect" }, 502);
  }
  const failed = auditFailure(
    await audit({ decision: "allow", outcome: "forwarded", upstreamStatus: upstream.status }),
  );
  if (failed) return failed;
  return new Response(upstream.body, {
    status: upstream.status,
    headers: forwardedResponseHeaders(upstream.headers),
  });
});

export default app;
