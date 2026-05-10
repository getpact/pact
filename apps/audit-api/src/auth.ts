import { AuthError, AuthzError, isUuid, ValidationError } from "@getpact/core";
import { verifyJwt } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { revokedJtis } from "@getpact/db/schema";
import { listVerifyingKeys } from "@getpact/keystore";
import { and, eq } from "drizzle-orm";
import { decodeJwt, decodeProtectedHeader } from "jose";

export type AuditAuthContext = {
  workspaceId: string;
  userId: string;
  email: string;
  roles: string[];
};

const stringArrayClaim = (value: unknown, name: string): string[] => {
  if (value === undefined) return [];
  if (Array.isArray(value) && value.every((v) => typeof v === "string")) return value;
  throw new AuthError(`invalid ${name} claim`);
};

export const authenticateAuditReader = async (
  databaseUrl: string,
  workspaceId: string,
  authHeader: string | undefined,
  audience: string,
  issuer: string,
): Promise<AuditAuthContext> => {
  if (!authHeader?.startsWith("Bearer ")) {
    throw new AuthError("missing or malformed Authorization header");
  }
  const token = authHeader.slice("Bearer ".length).trim();

  let claims: ReturnType<typeof decodeJwt>;
  try {
    claims = decodeJwt(token);
  } catch {
    throw new AuthError("malformed token");
  }
  const tokenWorkspace = claims.org as string | undefined;
  const sub = claims.sub;
  const jti = claims.jti as string | undefined;
  if (!tokenWorkspace || !sub || !jti) {
    throw new AuthError("missing required claims");
  }
  if (tokenWorkspace !== workspaceId) {
    throw new AuthError("token workspace mismatch");
  }
  if (!isUuid(workspaceId)) {
    throw new ValidationError("malformed workspace id");
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

  await verifyJwt(token, {
    publicKey: matched.publicKey,
    issuer,
    audience,
  });

  const revoked = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .select({ jti: revokedJtis.jti })
      .from(revokedJtis)
      .where(and(eq(revokedJtis.workspaceId, workspaceId), eq(revokedJtis.jti, jti)))
      .limit(1),
  );
  if (revoked.length > 0) {
    throw new AuthError("token revoked");
  }

  const roles = stringArrayClaim(claims.roles, "roles");
  if (!roles.includes("admin") && !roles.includes("auditor")) {
    throw new AuthzError("admin or auditor role required");
  }

  return {
    workspaceId,
    userId: sub,
    email: (claims.email as string | undefined) ?? "",
    roles,
  };
};
