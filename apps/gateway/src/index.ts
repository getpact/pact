import {
  assertAllowedUpstreamHost,
  assertSafeUpstreamUrl,
  isUuid,
  securityHeaders,
} from "@getpact/core";
import { fromBase64 } from "@getpact/crypto";
import { createClient, schema, withWorkspace } from "@getpact/db";
import { createLogger, requestLogger } from "@getpact/logger";
import { databaseRateLimiter } from "@getpact/ratelimit";
import { loadSecretString } from "@getpact/vault";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { decodeJwt } from "jose";
import { emitGatewayAudit } from "./audit.js";

type Env = {
  DATABASE_URL: string;
  VERIFIER_URL: string;
  MEK?: string;
  ENVIRONMENT?: string;
  GATEWAY_AUDIENCE?: string;
  VERIFIER_SERVICE_TOKEN?: string;
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
const MAX_RATE_LIMIT = 1000;
const MAX_RATE_WINDOW_SECONDS = 3600;

const parsePositiveInt = (raw: string | undefined, fallback: number, max: number): number => {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, max);
};

const gatewayAuditRequired = (env: Env): boolean => {
  const mode = env.GATEWAY_AUDIT_MODE?.trim();
  if (mode === "required") return true;
  if (mode === "best_effort") return false;
  return env.ENVIRONMENT === "production";
};

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
  search = "",
): { action: string; resource: string } => ({
  action: `gateway.${method.toLowerCase()}`,
  resource: `gateway:${brain}:/${path.replace(/^\/+/, "")}${canonicalGatewaySearch(search)}`,
});

export const canonicalGatewaySearch = (search: string): string => {
  const params = new URLSearchParams(search.startsWith("?") ? search.slice(1) : search);
  const entries = [...params.entries()].sort(([leftKey, leftValue], [rightKey, rightValue]) => {
    const keyOrder = leftKey.localeCompare(rightKey);
    return keyOrder === 0 ? leftValue.localeCompare(rightValue) : keyOrder;
  });
  if (entries.length === 0) return "";

  const canonical = new URLSearchParams();
  for (const [key, value] of entries) canonical.append(key, value);
  return `?${canonical.toString()}`;
};

const bearerToken = (value: string | undefined): string | null => {
  if (!value?.startsWith("Bearer ")) return null;
  const token = value.slice("Bearer ".length).trim();
  return token.length > 0 ? token : null;
};

const clientRateKey = (headers: Headers): string => {
  const cfIp = headers.get("cf-connecting-ip")?.trim();
  if (cfIp) return cfIp;
  const forwarded = headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return forwarded && forwarded.length > 0 ? forwarded : "anonymous";
};

export const verify = async (
  verifierUrl: string,
  input: { token: string; action: string; resource: string; audience: string },
  serviceToken?: string,
): Promise<VerifyOutput> => {
  try {
    const headers = new Headers({ "content-type": "application/json" });
    if (serviceToken) headers.set("authorization", `Bearer ${serviceToken}`);
    const res = await fetch(`${verifierUrl.replace(/\/+$/, "")}/v1/verify`, {
      method: "POST",
      headers,
      body: JSON.stringify(input),
    });
    const body = (await res.json()) as Partial<VerifyOutput>;
    const bodyOk = typeof body.allow === "boolean" && Array.isArray(body.reasons);
    if (bodyOk && (res.ok || res.status === 403)) {
      return { allow: body.allow as boolean, reasons: body.reasons as string[] };
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
  const requestUrl = new URL(c.req.url);
  const prefix = `/${workspaceParam}/gateway/${brainKind}/`;
  const path = requestUrl.pathname.startsWith(prefix)
    ? requestUrl.pathname.slice(prefix.length)
    : "";
  const audience = c.env.GATEWAY_AUDIENCE ?? "pact-gateway";
  const authz = gatewayAuthorization(c.req.method, brainKind, path, requestUrl.search);

  let claims: ReturnType<typeof decodeJwt>;
  try {
    claims = decodeJwt(token);
  } catch {
    return c.json({ error: "unauthorized", message: "malformed bearer token" }, 401);
  }
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

  const verdict = await verify(
    c.env.VERIFIER_URL,
    {
      token,
      action: authz.action,
      resource: authz.resource,
      audience,
    },
    c.env.VERIFIER_SERVICE_TOKEN,
  );

  const auditTarget = {
    resource: authz.resource,
    brain: brainKind,
    path: `/${path.replace(/^\/+/, "")}`,
    query: canonicalGatewaySearch(requestUrl.search),
    method: c.req.method,
  };
  const audit = async (input: {
    action?: string;
    decision: "allow" | "deny";
    outcome: string;
    upstreamStatus?: number;
    reasons?: string[];
  }) => {
    const actorId = verdict.allow && typeof claims.sub === "string" ? claims.sub : undefined;
    const result = await emitGatewayAudit({
      db,
      mek: c.env.MEK,
      workspaceId,
      actorId,
      action: input.action ?? authz.action,
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
      : c.json(
          {
            error: "audit_unavailable",
            message: `gateway audit is required (${result.reason})`,
          },
          503,
        );

  if (!verdict.allow) {
    const failed = auditFailure(await audit({ decision: "deny", outcome: "denied" }));
    if (failed) return failed;
    return c.json({ error: "denied", reasons: verdict.reasons }, 403);
  }

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

  if (c.env.ENVIRONMENT !== "test") {
    const limit = parsePositiveInt(c.env.GATEWAY_RATE_LIMIT, DEFAULT_RATE_LIMIT, MAX_RATE_LIMIT);
    const windowSeconds = parsePositiveInt(
      c.env.GATEWAY_RATE_WINDOW_SECONDS,
      DEFAULT_RATE_WINDOW_SECONDS,
      MAX_RATE_WINDOW_SECONDS,
    );
    const rateLimiter = databaseRateLimiter(c.env.DATABASE_URL);
    const verdictRate = await rateLimiter.hit(
      `gateway:${workspace.id}:${brainKind}:${clientRateKey(c.req.raw.headers)}`,
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

  let brainBearerToken: string | null = null;
  if (brain.authScheme === "bearer") {
    if (!c.env.MEK) {
      const failed = auditFailure(await audit({ decision: "deny", outcome: "mek_not_configured" }));
      if (failed) return failed;
      return c.json({ error: "misconfigured", message: "gateway MEK not configured" }, 500);
    }
    const rawMek = fromBase64(c.env.MEK);
    brainBearerToken = await withWorkspace(db, workspaceId, (tx) =>
      loadSecretString(tx, rawMek, {
        workspaceId,
        kind: "brain_credential",
        target: brainKind,
      }),
    );
    if (!brainBearerToken) {
      const failed = auditFailure(
        await audit({ decision: "deny", outcome: "brain_credential_missing" }),
      );
      if (failed) return failed;
      return c.json({ error: "credential_missing", message: "brain credential not in vault" }, 500);
    }
    if (/[\r\n\t]/.test(brainBearerToken)) {
      const failed = auditFailure(
        await audit({ decision: "deny", outcome: "brain_credential_invalid" }),
      );
      if (failed) return failed;
      return c.json(
        { error: "credential_invalid", message: "brain credential is not safe to forward" },
        500,
      );
    }
  } else if (brain.authScheme !== "none") {
    const failed = auditFailure(
      await audit({ decision: "deny", outcome: "unsupported_auth_scheme" }),
    );
    if (failed) return failed;
    return c.json(
      { error: "not_implemented", message: "gateway brain auth scheme not implemented" },
      501,
    );
  }

  let target: URL;
  try {
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

  const attemptFailed = auditFailure(
    await audit({ action: "gateway.attempt", decision: "allow", outcome: "attempt" }),
  );
  if (attemptFailed) return attemptFailed;

  const controller = new AbortController();
  const timeoutMs = upstreamTimeout(c.env);
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const outboundHeaders = forwardedRequestHeaders(c.req.raw.headers);
  if (brainBearerToken) outboundHeaders.set("authorization", `Bearer ${brainBearerToken}`);
  const init: RequestInit = {
    method: c.req.method,
    headers: outboundHeaders,
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
