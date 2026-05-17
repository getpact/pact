import { authenticateBearer } from "@getpact/auth";
import { AuthError, isUuid, NotFoundError } from "@getpact/core";
import { fromBase64Url } from "@getpact/crypto";
import { createClient } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { eq } from "drizzle-orm";

export type AuthContext = {
  kind?: "bearer" | "sd_jwt";
  workspaceId: string;
  userId: string;
  email: string;
  groups: string[];
  roles: string[];
  jti: string;
  token: string;
  agentId?: string;
  audience?: string;
};

const JWS_SEGMENT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

export const isSdJwtCompact = (bearer: string): boolean => {
  const tildeIdx = bearer.indexOf("~");
  if (tildeIdx < 0) return false;
  const first = bearer.slice(0, tildeIdx);
  return JWS_SEGMENT_RE.test(first);
};

type IssuerPayload = {
  org?: unknown;
  jti?: unknown;
  sub?: unknown;
  aud?: unknown;
  on_behalf_of?: unknown;
  email?: unknown;
};

const parseIssuerPayload = (compact: string): IssuerPayload | null => {
  try {
    const jws = compact.split("~")[0];
    if (!jws) return null;
    const seg = jws.split(".")[1];
    if (!seg) return null;
    const json = new TextDecoder().decode(fromBase64Url(seg));
    return JSON.parse(json) as IssuerPayload;
  } catch {
    return null;
  }
};

const resolveWorkspace = async (
  databaseUrl: string,
  workspaceId: string,
  workspaceSlug: string,
): Promise<void> => {
  const db = createClient(databaseUrl);
  const [workspace] = await db
    .select({ id: workspaces.id, slug: workspaces.slug })
    .from(workspaces)
    .where(eq(workspaces.id, workspaceId))
    .limit(1);
  if (!workspace) throw new NotFoundError("unknown workspace");
  if (workspaceSlug !== workspace.id && workspaceSlug !== workspace.slug) {
    throw new AuthError("token workspace mismatch");
  }
};

const authenticateSdJwt = async (
  databaseUrl: string,
  workspaceSlug: string,
  token: string,
): Promise<AuthContext> => {
  const payload = parseIssuerPayload(token);
  if (!payload) throw new AuthError("malformed sd-jwt");

  const workspaceId = typeof payload.org === "string" ? payload.org : null;
  const jti = typeof payload.jti === "string" ? payload.jti : null;
  const sub = typeof payload.sub === "string" ? payload.sub : null;
  const audience = typeof payload.aud === "string" ? payload.aud : null;
  if (!workspaceId || !jti || !sub || !audience) {
    throw new AuthError("missing required sd-jwt claims");
  }
  if (!isUuid(workspaceId) || !isUuid(jti)) {
    throw new AuthError("malformed sd-jwt identifiers");
  }

  await resolveWorkspace(databaseUrl, workspaceId, workspaceSlug);

  const agentId = sub.startsWith("agent_") ? sub.slice("agent_".length) : sub;
  const email = typeof payload.on_behalf_of === "string" ? payload.on_behalf_of : "";

  return {
    kind: "sd_jwt",
    workspaceId,
    userId: sub,
    email,
    groups: [],
    roles: [],
    jti,
    token,
    agentId,
    audience,
  };
};

export const authenticate = async (
  databaseUrl: string,
  workspaceSlug: string,
  authHeader: string | undefined,
  audience: string,
  issuer: string,
): Promise<AuthContext> => {
  if (!authHeader?.startsWith("Bearer ")) {
    throw new AuthError("missing or malformed Authorization header");
  }
  const raw = authHeader.slice("Bearer ".length).trim();

  if (isSdJwtCompact(raw)) {
    return authenticateSdJwt(databaseUrl, workspaceSlug, raw);
  }

  const { claims } = await authenticateBearer({ databaseUrl, authHeader, audience, issuer });
  await resolveWorkspace(databaseUrl, claims.workspaceId, workspaceSlug);
  return {
    kind: "bearer",
    workspaceId: claims.workspaceId,
    userId: claims.userId,
    email: claims.email,
    groups: claims.groups,
    roles: claims.roles,
    jti: claims.jti,
    token: claims.token,
  };
};
