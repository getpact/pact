import { ConflictError, canonicalizeEmail, type Email } from "@getpact/core";
import { createClient } from "@getpact/db";
import { roles, userRoles, users, workspaceAudiences, workspaces } from "@getpact/db/schema";
import { createSigningKey } from "@getpact/keystore";
import { sql } from "drizzle-orm";

const DEFAULT_AUDIENCES: ReadonlyArray<{ name: string; description: string }> = [
  { name: "pact-admin", description: "Workspace admin console" },
  { name: "pact-audit", description: "Audit log readers" },
  { name: "pact-mcp", description: "MCP gateway access" },
  { name: "pact-gateway", description: "Pact gateway" },
  { name: "pact-agent", description: "Agent capability tokens" },
];

const isPgUniqueViolation = (e: unknown): boolean =>
  typeof e === "object" && e !== null && "code" in e && (e as { code?: unknown }).code === "23505";

export type CreateWorkspaceInput = {
  slug: string;
  name: string;
  region?: string;
  adminEmail: string;
  adminName?: string;
};

export type CreateWorkspaceResult = {
  workspaceId: string;
  adminUserId: string;
  jwtKeyId: string;
  auditKeyId: string;
};

export const createWorkspace = async (
  databaseUrl: string,
  rawMek: Uint8Array,
  input: CreateWorkspaceInput,
): Promise<CreateWorkspaceResult> => {
  const db = createClient(databaseUrl);

  return db.transaction(async (tx) => {
    let ws: typeof workspaces.$inferSelect | undefined;
    try {
      [ws] = await tx
        .insert(workspaces)
        .values({ slug: input.slug, name: input.name, region: input.region ?? "us-east-1" })
        .returning();
    } catch (e) {
      if (isPgUniqueViolation(e)) throw new ConflictError("workspace slug already exists");
      throw e;
    }
    if (!ws) throw new Error("workspace insert failed");

    await tx.execute(sql`SELECT set_config('app.current_workspace_id', ${ws.id}, true)`);

    const email = canonicalizeEmail(input.adminEmail) as Email;
    const [user] = await tx
      .insert(users)
      .values({ workspaceId: ws.id, email, name: input.adminName ?? null })
      .returning();
    if (!user) throw new Error("admin user insert failed");

    const [adminRole] = await tx
      .insert(roles)
      .values({ workspaceId: ws.id, name: "admin", description: "Workspace admin" })
      .returning();
    if (!adminRole) throw new Error("admin role insert failed");

    await tx.insert(userRoles).values({ userId: user.id, roleId: adminRole.id });

    for (const aud of DEFAULT_AUDIENCES) {
      await tx.insert(workspaceAudiences).values({
        workspaceId: ws.id,
        name: aud.name,
        description: aud.description,
        createdByUserId: user.id,
      });
    }

    const jwtKey = await createSigningKey(tx, {
      workspaceId: ws.id,
      kind: "jwt",
      rawMek,
    });
    const auditKey = await createSigningKey(tx, {
      workspaceId: ws.id,
      kind: "audit",
      rawMek,
    });

    return {
      workspaceId: ws.id,
      adminUserId: user.id,
      jwtKeyId: jwtKey.id,
      auditKeyId: auditKey.id,
    };
  });
};
