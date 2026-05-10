import { sha256, toBase64, toHex } from "@getpact/crypto";
import type { Tx } from "@getpact/db";
import { refreshTokens } from "@getpact/db/schema";
import { and, eq, gt, isNull, sql } from "drizzle-orm";

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
  ttlSeconds: number;
};

export const issueRefresh = async (tx: Tx, input: IssueRefreshInput): Promise<IssuedRefresh> => {
  const raw = generateRefreshSecret();
  const hash = await hashRefresh(raw);
  const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000);
  const inserted = (await tx.execute(
    sql`INSERT INTO refresh_tokens (workspace_id, user_id, ciphertext, expires_at)
        VALUES (${input.workspaceId}, ${input.userId}, ${hash}, ${expiresAt.toISOString()})
        RETURNING id`,
  )) as Array<{ id: string }>;
  const id = inserted[0]?.id;
  if (!id) throw new Error("refresh insert returned no id");
  return { refreshToken: raw, refreshTokenId: id, expiresAt };
};

export type RedeemRefreshResult = {
  workspaceId: string;
  userId: string;
};

export const redeemRefresh = async (
  tx: Tx,
  workspaceId: string,
  rawRefresh: string,
): Promise<RedeemRefreshResult | null> => {
  const hash = await hashRefresh(rawRefresh);
  const now = new Date();
  const rows = await tx
    .select()
    .from(refreshTokens)
    .where(
      and(
        eq(refreshTokens.workspaceId, workspaceId),
        eq(refreshTokens.ciphertext, hash),
        gt(refreshTokens.expiresAt, now),
        isNull(refreshTokens.lastUsedAt),
      ),
    )
    .limit(1);

  const row = rows[0];
  if (!row) return null;

  await tx.execute(sql`UPDATE refresh_tokens SET last_used_at = NOW() WHERE id = ${row.id}`);
  return { workspaceId: row.workspaceId, userId: row.userId };
};
