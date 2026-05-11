import { writeEvent } from "@getpact/audit";
import { AuthzError, type Email, tokenModeForAudience, ValidationError } from "@getpact/core";
import { issueJwt } from "@getpact/crypto";
import { createClient, type Tx, withWorkspace } from "@getpact/db";
import { groupMembers, groups, roles, userRoles, users, workspaces } from "@getpact/db/schema";
import { loadActiveSigningKey } from "@getpact/keystore";
import { and, eq, sql } from "drizzle-orm";
import { type IssuedRefresh, issueRefresh } from "./refresh.js";

export type IssueTokenInput = {
  workspaceId: string;
  email: Email;
  googleSub?: string;
  audience: string;
  ttlSeconds: number;
  refreshTtlSeconds?: number;
  issuerUrl: string;
};

export type IssueTokenResult = {
  token: string;
  jti: string;
  exp: number;
  userId: string;
  refreshToken: string;
  refreshExpiresAt: string;
};

export type IssueTokenBundleInput = Omit<IssueTokenInput, "audience"> & {
  audiences: string[];
};

const newJti = () => crypto.randomUUID();
const DEFAULT_REFRESH_TTL = 24 * 60 * 60;

const pgErrorCode = (value: unknown): string | null => {
  if (typeof value !== "object" || value === null || !("code" in value)) return null;
  const code = (value as { code?: unknown }).code;
  return typeof code === "string" ? code : null;
};

const isUniqueViolation = (value: unknown): boolean => pgErrorCode(value) === "23505";

const tryAuditRefresh = async (
  tx: Tx,
  input: {
    workspaceId: string;
    rawMek: Uint8Array;
    decision: "allow" | "deny";
    userId?: string;
    audience: string;
    reason: string;
    oldAccessJti?: string | null;
    newAccessJti?: string;
  },
): Promise<void> => {
  try {
    const [ws] = await tx
      .select({ createdAt: workspaces.createdAt })
      .from(workspaces)
      .where(eq(workspaces.id, input.workspaceId))
      .limit(1);
    if (!ws) return;
    const auditKey = await loadActiveSigningKey(tx, input.workspaceId, "audit", input.rawMek);
    await writeEvent(tx, {
      workspaceId: input.workspaceId,
      workspaceCreatedAt: ws.createdAt,
      signingKeyId: auditKey.id,
      signingKey: auditKey.privateKey,
      event: {
        actorKind: input.userId ? "user" : "system",
        ...(input.userId ? { actorId: input.userId } : {}),
        action: input.decision === "allow" ? "issuer.refresh.succeeded" : "issuer.refresh.denied",
        target: { audience: input.audience },
        decision: input.decision,
        supporting: {
          reason: input.reason,
          oldAccessJti: input.oldAccessJti ?? null,
          newAccessJti: input.newAccessJti ?? null,
        },
      },
    });
  } catch {
    // best-effort: never fail token refresh because audit failed
  }
};

const issueAccessToken = async (
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
  const mode = tokenModeForAudience(input.audience);
  if (!mode) throw new ValidationError("unsupported token audience");

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
  const token = await issueJwt(
    {
      sub: input.userId,
      email: input.email,
      org: input.workspaceId,
      groups: userGroupRows.map((r) => r.name),
      roles: userRoleRows.map((r) => r.name),
      mode,
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

const loadAndBindUser = async (
  tx: Tx,
  input: { workspaceId: string; email: Email; googleSub?: string },
): Promise<{ id: string; email: string }> => {
  const rows = (await tx.execute(
    sql`SELECT id, email, google_sub AS "googleSub"
        FROM users
        WHERE workspace_id = ${input.workspaceId}
          AND email = ${input.email}
        LIMIT 1
        FOR UPDATE`,
  )) as Array<{ id: string; email: string; googleSub: string | null }>;
  const user = rows[0];
  if (!user) throw new AuthzError("user not in workspace");
  if (input.googleSub) {
    if (user.googleSub && user.googleSub !== input.googleSub) {
      throw new AuthzError("google identity mismatch");
    }
    if (!user.googleSub) {
      let updated: Array<{ id: string }>;
      try {
        updated = await tx
          .update(users)
          .set({ googleSub: input.googleSub })
          .where(and(eq(users.id, user.id), sql`${users.googleSub} IS NULL`))
          .returning({ id: users.id });
      } catch (e) {
        if (isUniqueViolation(e)) throw new AuthzError("google identity mismatch");
        throw e;
      }
      if (updated.length === 0) throw new AuthzError("google identity mismatch");
    }
  }
  return { id: user.id, email: user.email };
};

const issueTokenForUser = async (
  tx: Tx,
  rawMek: Uint8Array,
  input: IssueTokenInput & { userId: string; userEmail: string },
): Promise<IssueTokenResult> => {
  const access = await issueAccessToken(tx, {
    workspaceId: input.workspaceId,
    userId: input.userId,
    email: input.userEmail,
    audience: input.audience,
    ttlSeconds: input.ttlSeconds,
    issuerUrl: input.issuerUrl,
    rawMek,
  });

  const refresh: IssuedRefresh = await issueRefresh(tx, {
    workspaceId: input.workspaceId,
    userId: input.userId,
    audience: input.audience,
    accessJti: access.jti,
    ttlSeconds: input.refreshTtlSeconds ?? DEFAULT_REFRESH_TTL,
  });

  return {
    ...access,
    userId: input.userId,
    refreshToken: refresh.refreshToken,
    refreshExpiresAt: refresh.expiresAt.toISOString(),
  };
};

export const issueTokenForEmail = async (
  databaseUrl: string,
  rawMek: Uint8Array,
  input: IssueTokenInput,
): Promise<IssueTokenResult> => {
  const db = createClient(databaseUrl);
  return withWorkspace(db, input.workspaceId, async (tx) => {
    const user = await loadAndBindUser(tx, input);
    return issueTokenForUser(tx, rawMek, {
      ...input,
      userId: user.id,
      userEmail: user.email,
    });
  });
};

export const issueTokenBundleForEmail = async (
  databaseUrl: string,
  rawMek: Uint8Array,
  input: IssueTokenBundleInput,
): Promise<Record<string, IssueTokenResult>> => {
  const db = createClient(databaseUrl);
  return withWorkspace(db, input.workspaceId, async (tx) => {
    const user = await loadAndBindUser(tx, input);
    const tokens: Record<string, IssueTokenResult> = {};
    for (const audience of input.audiences) {
      tokens[audience] = await issueTokenForUser(tx, rawMek, {
        ...input,
        audience,
        userId: user.id,
        userEmail: user.email,
      });
    }
    return tokens;
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

export const redeemRefreshAndIssue = async (
  databaseUrl: string,
  rawMek: Uint8Array,
  input: RedeemTokenInput,
): Promise<IssueTokenResult | null> => {
  const { redeemRefresh } = await import("./refresh.js");
  const db = createClient(databaseUrl);
  return withWorkspace(db, input.workspaceId, async (tx) => {
    const redeemed = await redeemRefresh(tx, input.workspaceId, input.refreshToken, input.audience);
    if (!redeemed) {
      await tryAuditRefresh(tx, {
        workspaceId: input.workspaceId,
        rawMek,
        decision: "deny",
        audience: input.audience,
        reason: "invalid_grant",
      });
      return null;
    }

    const [user] = await tx.select().from(users).where(eq(users.id, redeemed.userId)).limit(1);
    if (!user) {
      await tryAuditRefresh(tx, {
        workspaceId: input.workspaceId,
        rawMek,
        decision: "deny",
        userId: redeemed.userId,
        audience: input.audience,
        reason: "user_not_found",
        oldAccessJti: redeemed.accessJti,
      });
      return null;
    }

    const access = await issueAccessToken(tx, {
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
      audience: input.audience,
      accessJti: access.jti,
      ttlSeconds: input.refreshTtlSeconds ?? DEFAULT_REFRESH_TTL,
    });

    await tryAuditRefresh(tx, {
      workspaceId: input.workspaceId,
      rawMek,
      decision: "allow",
      userId: user.id,
      audience: input.audience,
      reason: "rotated",
      oldAccessJti: redeemed.accessJti,
      newAccessJti: access.jti,
    });

    return {
      ...access,
      userId: user.id,
      refreshToken: refresh.refreshToken,
      refreshExpiresAt: refresh.expiresAt.toISOString(),
    };
  });
};
