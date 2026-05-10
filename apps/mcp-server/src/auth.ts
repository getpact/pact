import { authenticateBearer } from "@getpact/auth";
import { AuthError, NotFoundError } from "@getpact/core";
import { createClient } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { eq } from "drizzle-orm";

export type AuthContext = {
  workspaceId: string;
  userId: string;
  email: string;
  groups: string[];
  roles: string[];
  jti: string;
  token: string;
};

export const authenticate = async (
  databaseUrl: string,
  workspaceSlug: string,
  authHeader: string | undefined,
  audience: string,
  issuer: string,
): Promise<AuthContext> => {
  const { claims } = await authenticateBearer({ databaseUrl, authHeader, audience, issuer });
  const db = createClient(databaseUrl);
  const [workspace] = await db
    .select({ id: workspaces.id, slug: workspaces.slug })
    .from(workspaces)
    .where(eq(workspaces.id, claims.workspaceId))
    .limit(1);
  if (!workspace) throw new NotFoundError("unknown workspace");
  if (workspaceSlug !== workspace.id && workspaceSlug !== workspace.slug) {
    throw new AuthError("token workspace mismatch");
  }
  return {
    workspaceId: claims.workspaceId,
    userId: claims.userId,
    email: claims.email,
    groups: claims.groups,
    roles: claims.roles,
    jti: claims.jti,
    token: claims.token,
  };
};
