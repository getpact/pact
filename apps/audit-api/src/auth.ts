import { verifyJwt } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { listVerifyingKeys } from "@getpact/keystore";
import { decodeJwt, decodeProtectedHeader } from "jose";

export type AuditAuthContext = {
  workspaceId: string;
  userId: string;
  email: string;
  roles: string[];
};

export const authenticateAuditReader = async (
  databaseUrl: string,
  workspaceId: string,
  authHeader: string | undefined,
  audience: string,
  issuer: string,
): Promise<AuditAuthContext> => {
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
  const tokenWorkspace = claims.org as string | undefined;
  const sub = claims.sub;
  if (!tokenWorkspace || !sub) {
    throw new Error("missing required claims");
  }
  if (tokenWorkspace !== workspaceId) {
    throw new Error("token workspace mismatch");
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

  const roles = (claims.scopes as string[] | undefined) ?? [];
  if (!roles.includes("admin") && !roles.includes("auditor")) {
    throw new Error("admin or auditor role required");
  }

  return {
    workspaceId,
    userId: sub,
    email: (claims.email as string | undefined) ?? "",
    roles,
  };
};
