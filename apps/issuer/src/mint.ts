import { type Email } from "@getpact/core";
import { mintJwt } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { groupMembers, groups, roles, userRoles, users } from "@getpact/db/schema";
import { loadActiveSigningKey } from "@getpact/keystore";
import { and, eq } from "drizzle-orm";

export type MintTokenInput = {
  workspaceId: string;
  email: Email;
  audience: string;
  ttlSeconds: number;
  issuerUrl: string;
};

export type MintTokenResult = {
  token: string;
  jti: string;
  exp: number;
  userId: string;
};

const newJti = () => crypto.randomUUID();

export const mintTokenForEmail = async (
  databaseUrl: string,
  rawMek: Uint8Array,
  input: MintTokenInput,
): Promise<MintTokenResult> => {
  const db = createClient(databaseUrl);
  return withWorkspace(db, input.workspaceId, async (tx) => {
    const [user] = await tx
      .select()
      .from(users)
      .where(and(eq(users.workspaceId, input.workspaceId), eq(users.email, input.email)))
      .limit(1);
    if (!user) throw new Error("user not found in workspace");

    const userRoleRows = await tx
      .select({ name: roles.name })
      .from(userRoles)
      .innerJoin(roles, eq(userRoles.roleId, roles.id))
      .where(eq(userRoles.userId, user.id));

    const userGroupRows = await tx
      .select({ name: groups.name })
      .from(groupMembers)
      .innerJoin(groups, eq(groupMembers.groupId, groups.id))
      .where(eq(groupMembers.userId, user.id));

    const key = await loadActiveSigningKey(tx, input.workspaceId, "jwt", rawMek);
    const jti = newJti();
    const ttl = input.ttlSeconds;

    const token = await mintJwt(
      {
        sub: user.id,
        email: user.email,
        org: input.workspaceId,
        groups: userGroupRows.map((r) => r.name),
        scopes: userRoleRows.map((r) => r.name),
        mode: "A",
      },
      {
        privateKey: key.privateKey,
        kid: key.id,
        issuer: input.issuerUrl,
        audience: input.audience,
        ttlSeconds: ttl,
        jti,
      },
    );

    return {
      token,
      jti,
      exp: Math.floor(Date.now() / 1000) + ttl,
      userId: user.id,
    };
  });
};
