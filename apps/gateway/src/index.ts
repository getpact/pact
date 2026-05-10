import { assertSafeUpstreamUrl, isUuid, securityHeaders } from "@getpact/core";
import { createClient, schema, withWorkspace } from "@getpact/db";
import { createLogger, requestLogger } from "@getpact/logger";
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
  GATEWAY_UPSTREAM_TIMEOUT_MS?: string;
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

const logger = createLogger({ base: { app: "gateway" } });

type VerifyOutput = {
  allow: boolean;
  reasons: string[];
};

export const buildGatewayTarget = (baseUrl: string, path: string, search: string): URL => {
  const target = assertSafeUpstreamUrl(baseUrl);
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
};

const forwardedRequestHeaders = (headers: Headers): Headers => {
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
  const audit = (input: {
    decision: "allow" | "deny";
    outcome: string;
    upstreamStatus?: number;
    reasons?: string[];
  }) =>
    emitGatewayAudit({
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
    await audit({ decision: "deny", outcome: "brain_not_found" });
    return c.json({ error: "not_found", message: "brain not found" }, 404);
  }
  if (brain.authScheme !== "none") {
    await audit({ decision: "deny", outcome: "unsupported_auth_scheme" });
    return c.json(
      { error: "not_implemented", message: "gateway brain auth is not implemented" },
      501,
    );
  }

  let target: URL;
  try {
    const requestUrl = new URL(c.req.url);
    target = buildGatewayTarget(brain.baseUrl, path, requestUrl.search);
  } catch (e) {
    const message = e instanceof Error ? e.message : "invalid gateway upstream";
    await audit({ decision: "deny", outcome: "invalid_upstream", reasons: [message] });
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
    await audit({ decision: "deny", outcome: aborted ? "timeout" : "upstream_failed" });
    return aborted
      ? c.json({ error: "gateway_timeout", message: "upstream request timed out" }, 504)
      : c.json({ error: "bad_gateway", message: "upstream request failed" }, 502);
  }
  clearTimeout(timer);
  if (upstream.status >= 300 && upstream.status < 400) {
    await audit({ decision: "deny", outcome: "redirect", upstreamStatus: upstream.status });
    return c.json({ error: "bad_gateway", message: "upstream returned redirect" }, 502);
  }
  await audit({ decision: "allow", outcome: "forwarded", upstreamStatus: upstream.status });
  return new Response(upstream.body, {
    status: upstream.status,
    headers: forwardedResponseHeaders(upstream.headers),
  });
});

export default app;
