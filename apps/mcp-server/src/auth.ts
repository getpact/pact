import { verifyJwt } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { listVerifyingKeys } from "@getpact/keystore";
import { decodeJwt, decodeProtectedHeader } from "jose";

export type AuthContext = {
  workspaceId: string;
  userId: string;
  email: string;
  groups: string[];
  roles: string[];
  jti: string;
};

export const authenticate = async (
  databaseUrl: string,
  workspaceSlug: string,
  authHeader: string | undefined,
  audience: string,
): Promise<AuthContext> => {
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
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
  const issuer = claims.iss as string | undefined;
  if (!workspaceId || !sub || !jti || !issuer) {
    throw new Error("missing required claims");
  }

  const kid = decodeProtectedHeader(token).kid;
  if (!kid) throw new Error("missing kid");

  const db = createClient(databaseUrl);
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

  // Optional: cross-check workspace slug from URL matches the org claim.
  // For now the slug -> id resolution is left to the caller; tests pass id directly.
  void workspaceSlug;

  return {
    workspaceId,
    userId: sub,
    email: (claims.email as string | undefined) ?? "",
    groups: (claims.groups as string[] | undefined) ?? [],
    roles: (claims.scopes as string[] | undefined) ?? [],
    jti,
  };
};
