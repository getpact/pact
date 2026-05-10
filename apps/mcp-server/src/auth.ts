import { isUuid } from "@getpact/core";
import { verifyJwt } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { revokedJtis, workspaces } from "@getpact/db/schema";
import { listVerifyingKeys } from "@getpact/keystore";
import { and, eq } from "drizzle-orm";
import { decodeJwt, decodeProtectedHeader } from "jose";

export type AuthContext = {
  workspaceId: string;
  userId: string;
  email: string;
  groups: string[];
  roles: string[];
  jti: string;
  token: string;
};

const stringArrayClaim = (value: unknown, name: string): string[] => {
  if (value === undefined) return [];
  if (Array.isArray(value) && value.every((v) => typeof v === "string")) return value;
  throw new Error(`invalid ${name} claim`);
};

export const authenticate = async (
  databaseUrl: string,
  workspaceSlug: string,
  authHeader: string | undefined,
  audience: string,
  issuer: string,
): Promise<AuthContext> => {
  if (!authHeader?.startsWith("Bearer ")) {
    throw new Error("missing or malformed Authorization header");
  }
  const token = authHeader.slice("Bearer ".length).trim();

  let claims: ReturnType<typeof decodeJwt>;
  try {
    claims = decodeJwt(token);
  } catch {
    throw new Error("malformed token");
  }
  const workspaceId = claims.org as string | undefined;
  const sub = claims.sub;
  const jti = claims.jti as string | undefined;
  if (!workspaceId || !sub || !jti) {
    throw new Error("missing required claims");
  }
  if (!isUuid(workspaceId)) {
    throw new Error("malformed workspace id");
  }

  let kid: string | undefined;
  try {
    kid = decodeProtectedHeader(token).kid;
  } catch {
    throw new Error("malformed token header");
  }
  if (!kid) throw new Error("missing kid");

  const db = createClient(databaseUrl);
  const [workspace] = await db
    .select({ id: workspaces.id, slug: workspaces.slug })
    .from(workspaces)
    .where(eq(workspaces.id, workspaceId))
    .limit(1);
  if (!workspace) throw new Error("unknown workspace");
  if (workspaceSlug !== workspace.id && workspaceSlug !== workspace.slug) {
    throw new Error("token workspace mismatch");
  }

  const keys = await withWorkspace(db, workspaceId, (tx) =>
    listVerifyingKeys(tx, workspaceId, "jwt"),
  );
  const matched = keys.find((k) => k.id === kid);
  if (!matched) throw new Error("unknown kid");

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
    throw new Error("token revoked");
  }

  return {
    workspaceId,
    userId: sub,
    email: (claims.email as string | undefined) ?? "",
    groups: stringArrayClaim(claims.groups, "groups"),
    roles: stringArrayClaim(claims.roles, "roles"),
    jti,
    token,
  };
};
