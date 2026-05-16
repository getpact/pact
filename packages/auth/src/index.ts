import { AuthError, isUuid, tokenModeForAudience } from "@getpact/core";
import { verifyJwt } from "@getpact/crypto";
import { createClient, type DbClient, withWorkspace } from "@getpact/db";
import { revokedJtis } from "@getpact/db/schema";
import { listVerifyingKeys } from "@getpact/keystore";
import { and, eq } from "drizzle-orm";
import { decodeJwt, decodeProtectedHeader } from "jose";

export type BearerClaims = {
  workspaceId: string;
  userId: string;
  email: string;
  groups: string[];
  roles: string[];
  jti: string;
  token: string;
};

export type AuthenticateBearerInput = {
  databaseUrl: string;
  authHeader: string | undefined;
  audience: string;
  issuer: string;
  expectedWorkspaceId?: string;
};

export type CallerLike = { email?: string; groups?: string[] };

export const callerAudience = (ctx: CallerLike): string[] => {
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (raw: string | undefined) => {
    if (typeof raw !== "string") return;
    const value = raw.trim();
    if (value.length === 0 || seen.has(value)) return;
    seen.add(value);
    out.push(value);
  };
  push(ctx.email);
  if (Array.isArray(ctx.groups)) {
    for (const g of ctx.groups) push(g);
  }
  return out;
};

export const stringArrayClaim = (value: unknown, name: string): string[] => {
  if (value === undefined) return [];
  if (Array.isArray(value) && value.every((v) => typeof v === "string")) return value;
  throw new AuthError(`invalid ${name} claim`);
};

export const authenticateBearer = async (
  input: AuthenticateBearerInput,
): Promise<{ claims: BearerClaims; db: DbClient }> => {
  const { authHeader, audience, issuer, databaseUrl, expectedWorkspaceId } = input;
  if (!authHeader?.startsWith("Bearer ")) {
    throw new AuthError("missing or malformed Authorization header");
  }
  const token = authHeader.slice("Bearer ".length).trim();

  let raw: ReturnType<typeof decodeJwt>;
  try {
    raw = decodeJwt(token);
  } catch {
    throw new AuthError("malformed token");
  }
  const workspaceId = raw.org as string | undefined;
  const sub = raw.sub;
  const jti = raw.jti as string | undefined;
  if (!workspaceId || !sub || !jti) {
    throw new AuthError("missing required claims");
  }
  if (!isUuid(workspaceId)) {
    throw new AuthError("malformed workspace id");
  }
  if (expectedWorkspaceId && expectedWorkspaceId !== workspaceId) {
    throw new AuthError("token workspace mismatch");
  }

  let kid: string | undefined;
  try {
    kid = decodeProtectedHeader(token).kid;
  } catch {
    throw new AuthError("malformed token header");
  }
  if (!kid) throw new AuthError("missing kid");

  const db = createClient(databaseUrl);
  const keys = await withWorkspace(db, workspaceId, (tx) =>
    listVerifyingKeys(tx, workspaceId, "jwt"),
  );
  const matched = keys.find((k) => k.id === kid);
  if (!matched) throw new AuthError("unknown kid");

  await verifyJwt(token, { publicKey: matched.publicKey, issuer, audience });

  const expectedMode = tokenModeForAudience(audience);
  if (!expectedMode || raw.mode !== expectedMode) {
    throw new AuthError("token mode mismatch");
  }

  const revoked = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .select({ jti: revokedJtis.jti })
      .from(revokedJtis)
      .where(and(eq(revokedJtis.workspaceId, workspaceId), eq(revokedJtis.jti, jti)))
      .limit(1),
  );
  if (revoked.length > 0) throw new AuthError("token revoked");

  return {
    db,
    claims: {
      workspaceId,
      userId: sub,
      email: (raw.email as string | undefined) ?? "",
      groups: stringArrayClaim(raw.groups, "groups"),
      roles: stringArrayClaim(raw.roles, "roles"),
      jti,
      token,
    },
  };
};
