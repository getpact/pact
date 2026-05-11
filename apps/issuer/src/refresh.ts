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
};

export const issueRefresh = async (tx: Tx, input: IssueRefreshInput): Promise<IssuedRefresh> => {
  const raw = generateRefreshSecret();
  const hash = await hashRefresh(raw);
  const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000);
  const inserted = (await tx.execute(
    sql`INSERT INTO refresh_tokens (workspace_id, user_id, ciphertext, audience, access_jti, expires_at)
        VALUES (${input.workspaceId}, ${input.userId}, ${hash}, ${input.audience}, ${input.accessJti}, ${expiresAt.toISOString()})
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
};

export const redeemRefresh = async (
  tx: Tx,
  workspaceId: string,
  rawRefresh: string,
  audience: string,
): Promise<RedeemRefreshResult | null> => {
  const hash = await hashRefresh(rawRefresh);
  const candidate = (await tx.execute(
    sql`SELECT user_id
        FROM refresh_tokens
        WHERE workspace_id = ${workspaceId}
          AND ciphertext = ${hash}
          AND audience = ${audience}
          AND expires_at > NOW()
          AND last_used_at IS NULL
          AND revoked_at IS NULL
        LIMIT 1`,
  )) as Array<{ user_id: string }>;
  const userId = candidate[0]?.user_id;
  if (!userId) return null;

  const lockedUser = (await tx.execute(
    sql`SELECT id
        FROM users
        WHERE workspace_id = ${workspaceId}
          AND id = ${userId}
        FOR UPDATE`,
  )) as Array<{ id: string }>;
  if (!lockedUser[0]) return null;

  // Atomic redeem: claim the row by setting last_used_at, only succeeds if
  // not already used and not expired. Concurrent redeems collide here.
  const claimed = (await tx.execute(
    sql`UPDATE refresh_tokens
        SET last_used_at = NOW()
        WHERE workspace_id = ${workspaceId}
          AND ciphertext = ${hash}
          AND audience = ${audience}
          AND expires_at > NOW()
          AND last_used_at IS NULL
          AND revoked_at IS NULL
        RETURNING workspace_id, user_id, access_jti`,
  )) as Array<{ workspace_id: string; user_id: string; access_jti: string | null }>;
  const row = claimed[0];
  if (!row) return null;
  return { workspaceId: row.workspace_id, userId: row.user_id, accessJti: row.access_jti };
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
