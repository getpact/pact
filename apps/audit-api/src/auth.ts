import { authenticateBearer } from "@getpact/auth";
import { AuthzError } from "@getpact/core";

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
  const { claims } = await authenticateBearer({
    databaseUrl,
    authHeader,
    audience,
    issuer,
    expectedWorkspaceId: workspaceId,
  });
  if (!claims.roles.includes("admin") && !claims.roles.includes("auditor")) {
    throw new AuthzError("admin or auditor role required");
  }
  return {
    workspaceId: claims.workspaceId,
    userId: claims.userId,
    email: claims.email,
    roles: claims.roles,
  };
};
