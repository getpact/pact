import { authenticateBearer } from "@getpact/auth";
import { AuthzError } from "@getpact/core";

export type AdminContext = {
  workspaceId: string;
  userId: string;
  email: string;
  groups: string[];
  roles: string[];
};

export const authenticateAdmin = async (
  databaseUrl: string,
  workspaceId: string,
  authHeader: string | undefined,
  audience: string,
  issuer: string,
): Promise<AdminContext> => {
  const { claims } = await authenticateBearer({
    databaseUrl,
    authHeader,
    audience,
    issuer,
    expectedWorkspaceId: workspaceId,
  });
  if (!claims.roles.includes("admin")) {
    throw new AuthzError("admin role required");
  }
  return {
    workspaceId: claims.workspaceId,
    userId: claims.userId,
    email: claims.email,
    groups: claims.groups,
    roles: claims.roles,
  };
};
