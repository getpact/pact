import { sha256, toBase64, toHex } from "@getpact/crypto";
import type { Tx } from "@getpact/db";
import { sql } from "drizzle-orm";

const REFRESH_BYTE_LEN = 32;

export type IssuedRefresh = {
  refreshToken: string;
  refreshTokenId: string;
  expiresAt: Date;
};

const generateRefreshSecret = (): string => {
  const buf = new Uint8Array(REFRESH_BYTE_LEN);
  crypto.getRandomValues(buf);
  return toBase64(buf).replace(/=+$/, "");
};

const hashRefresh = async (raw: string): Promise<string> =>
  toHex(await sha256(new TextEncoder().encode(raw)));

export type IssueRefreshInput = {
  workspaceId: string;
  userId: string;
  audience: string;
  accessJti: string;
  ttlSeconds: number;
  familyId?: string;
  parentId?: string;
};

export const issueRefresh = async (tx: Tx, input: IssueRefreshInput): Promise<IssuedRefresh> => {
  const raw = generateRefreshSecret();
  const hash = await hashRefresh(raw);
  const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000);
  const familyId = input.familyId ?? null;
  const parentId = input.parentId ?? null;
  const inserted = (await tx.execute(
    sql`INSERT INTO refresh_tokens (workspace_id, user_id, ciphertext, audience, access_jti, expires_at, family_id, parent_id)
        VALUES (
          ${input.workspaceId}, ${input.userId}, ${hash}, ${input.audience}, ${input.accessJti}, ${expiresAt.toISOString()},
          COALESCE(${familyId}::uuid, gen_random_uuid()), ${parentId}::uuid
        )
        RETURNING id`,
  )) as Array<{ id: string }>;
  const id = inserted[0]?.id;
  if (!id) throw new Error("refresh insert returned no id");
  return { refreshToken: raw, refreshTokenId: id, expiresAt };
};

export type RedeemRefreshResult = {
  workspaceId: string;
  userId: string;
  accessJti: string | null;
  refreshTokenId: string;
  familyId: string;
};

export type RefreshReuseDetection = {
  refreshTokenId: string;
  familyId: string;
  userId: string;
};

export type RedeemRefreshOutcome =
  | { kind: "ok"; redeemed: RedeemRefreshResult }
  | { kind: "reuse"; detection: RefreshReuseDetection }
  | { kind: "miss" };

export const redeemRefresh = async (
  tx: Tx,
  workspaceId: string,
  rawRefresh: string,
  audience: string,
): Promise<RedeemRefreshResult | null> => {
  const outcome = await redeemRefreshDetailed(tx, workspaceId, rawRefresh, audience);
  return outcome.kind === "ok" ? outcome.redeemed : null;
};

export const redeemRefreshDetailed = async (
  tx: Tx,
  workspaceId: string,
  rawRefresh: string,
  audience: string,
): Promise<RedeemRefreshOutcome> => {
  const hash = await hashRefresh(rawRefresh);
  const candidate = (await tx.execute(
    sql`SELECT id, user_id, family_id, last_used_at, revoked_at, expires_at
        FROM refresh_tokens
        WHERE workspace_id = ${workspaceId}
          AND ciphertext = ${hash}
          AND audience = ${audience}
        LIMIT 1`,
  )) as Array<{
    id: string;
    user_id: string;
    family_id: string;
    last_used_at: Date | null;
    revoked_at: Date | null;
    expires_at: Date;
  }>;
  const row = candidate[0];
  if (!row) return { kind: "miss" };

  if (row.last_used_at !== null || row.revoked_at !== null) {
    await tx.execute(
      sql`UPDATE refresh_tokens
          SET revoked_at = COALESCE(revoked_at, NOW())
          WHERE workspace_id = ${workspaceId}
            AND family_id = ${row.family_id}`,
    );
    return {
      kind: "reuse",
      detection: { refreshTokenId: row.id, familyId: row.family_id, userId: row.user_id },
    };
  }

  if (new Date(row.expires_at).getTime() <= Date.now()) {
    return { kind: "miss" };
  }

  const lockedUser = (await tx.execute(
    sql`SELECT id
        FROM users
        WHERE workspace_id = ${workspaceId}
          AND id = ${row.user_id}
        FOR UPDATE`,
  )) as Array<{ id: string }>;
  if (!lockedUser[0]) return { kind: "miss" };

  const claimed = (await tx.execute(
    sql`UPDATE refresh_tokens
        SET last_used_at = NOW()
        WHERE workspace_id = ${workspaceId}
          AND ciphertext = ${hash}
          AND audience = ${audience}
          AND expires_at > NOW()
          AND last_used_at IS NULL
          AND revoked_at IS NULL
        RETURNING id, workspace_id, user_id, access_jti, family_id`,
  )) as Array<{
    id: string;
    workspace_id: string;
    user_id: string;
    access_jti: string | null;
    family_id: string;
  }>;
  const won = claimed[0];
  if (!won) return { kind: "miss" };
  return {
    kind: "ok",
    redeemed: {
      workspaceId: won.workspace_id,
      userId: won.user_id,
      accessJti: won.access_jti,
      refreshTokenId: won.id,
      familyId: won.family_id,
    },
  };
};

export const revokeRefreshForAccessJti = async (
  tx: Tx,
  workspaceId: string,
  accessJti: string,
): Promise<void> => {
  await tx.execute(
    sql`UPDATE refresh_tokens
        SET revoked_at = COALESCE(revoked_at, NOW())
        WHERE workspace_id = ${workspaceId}
          AND access_jti = ${accessJti}
          AND revoked_at IS NULL`,
  );
};
