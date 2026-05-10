import type { Email } from "@getpact/core";
import { mintJwt } from "@getpact/crypto";
import { createClient, type Tx, withWorkspace } from "@getpact/db";
import { groupMembers, groups, roles, userRoles, users } from "@getpact/db/schema";
import { loadActiveSigningKey } from "@getpact/keystore";
import { and, eq } from "drizzle-orm";
import { type IssuedRefresh, issueRefresh } from "./refresh.js";

export type MintTokenInput = {
  workspaceId: string;
  email: Email;
  audience: string;
  ttlSeconds: number;
  refreshTtlSeconds?: number;
  issuerUrl: string;
};

export type MintTokenResult = {
  token: string;
  jti: string;
  exp: number;
  userId: string;
  refreshToken: string;
  refreshExpiresAt: string;
};

const newJti = () => crypto.randomUUID();
const DEFAULT_REFRESH_TTL = 24 * 60 * 60;

const mintAccessToken = async (
  tx: Tx,
  input: {
    workspaceId: string;
    userId: string;
    email: string;
    audience: string;
    ttlSeconds: number;
    issuerUrl: string;
    rawMek: Uint8Array;
  },
): Promise<{ token: string; jti: string; exp: number }> => {
  const userRoleRows = await tx
    .select({ name: roles.name })
    .from(userRoles)
    .innerJoin(roles, eq(userRoles.roleId, roles.id))
    .where(eq(userRoles.userId, input.userId));

  const userGroupRows = await tx
    .select({ name: groups.name })
    .from(groupMembers)
    .innerJoin(groups, eq(groupMembers.groupId, groups.id))
    .where(eq(groupMembers.userId, input.userId));

  const key = await loadActiveSigningKey(tx, input.workspaceId, "jwt", input.rawMek);
  const jti = newJti();
  const token = await mintJwt(
    {
      sub: input.userId,
      email: input.email,
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
      ttlSeconds: input.ttlSeconds,
      jti,
    },
  );
  return { token, jti, exp: Math.floor(Date.now() / 1000) + input.ttlSeconds };
};

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

    const access = await mintAccessToken(tx, {
      workspaceId: input.workspaceId,
      userId: user.id,
      email: user.email,
      audience: input.audience,
      ttlSeconds: input.ttlSeconds,
      issuerUrl: input.issuerUrl,
      rawMek,
    });

    const refresh: IssuedRefresh = await issueRefresh(tx, {
      workspaceId: input.workspaceId,
      userId: user.id,
      ttlSeconds: input.refreshTtlSeconds ?? DEFAULT_REFRESH_TTL,
    });

    return {
      ...access,
      userId: user.id,
      refreshToken: refresh.refreshToken,
      refreshExpiresAt: refresh.expiresAt.toISOString(),
    };
  });
};

export type RedeemTokenInput = {
  workspaceId: string;
  refreshToken: string;
  audience: string;
  ttlSeconds: number;
  refreshTtlSeconds?: number;
  issuerUrl: string;
};

export const redeemRefreshAndMint = async (
  databaseUrl: string,
  rawMek: Uint8Array,
  input: RedeemTokenInput,
): Promise<MintTokenResult | null> => {
  const { redeemRefresh } = await import("./refresh.js");
  const db = createClient(databaseUrl);
  return withWorkspace(db, input.workspaceId, async (tx) => {
    const redeemed = await redeemRefresh(tx, input.workspaceId, input.refreshToken);
    if (!redeemed) return null;

    const [user] = await tx.select().from(users).where(eq(users.id, redeemed.userId)).limit(1);
    if (!user) return null;

    const access = await mintAccessToken(tx, {
      workspaceId: input.workspaceId,
      userId: user.id,
      email: user.email,
      audience: input.audience,
      ttlSeconds: input.ttlSeconds,
      issuerUrl: input.issuerUrl,
      rawMek,
    });

    const refresh = await issueRefresh(tx, {
      workspaceId: input.workspaceId,
      userId: user.id,
      ttlSeconds: input.refreshTtlSeconds ?? DEFAULT_REFRESH_TTL,
    });

    return {
      ...access,
      userId: user.id,
      refreshToken: refresh.refreshToken,
      refreshExpiresAt: refresh.expiresAt.toISOString(),
    };
  });
};
