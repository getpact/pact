import { importAesKey } from "@getpact/crypto";
import type { Tx } from "@getpact/db";
import { vaultSecrets } from "@getpact/db/schema";
import { and, eq, sql } from "drizzle-orm";
import { unwrapSecret, wrapSecret } from "./envelope.js";

export type StoreSecretInput = {
  workspaceId: string;
  kind: string;
  target: string;
  plaintext: Uint8Array | string;
};

export type StoredSecret = {
  id: string;
  kind: string;
  target: string;
  createdAt: Date;
  rotatedAt: Date | null;
};

const toBytes = (v: Uint8Array | string): Uint8Array =>
  typeof v === "string" ? new TextEncoder().encode(v) : v;

export const storeSecret = async (
  tx: Tx,
  rawMek: Uint8Array,
  input: StoreSecretInput,
): Promise<StoredSecret> => {
  const mek = await importAesKey(rawMek);
  const wrapped = await wrapSecret(mek, toBytes(input.plaintext));
  const inserted = (await tx.execute(
    sql`INSERT INTO vault_secrets (workspace_id, kind, target, ciphertext, dek_ciphertext)
        VALUES (${input.workspaceId}, ${input.kind}, ${input.target}, ${wrapped.ciphertext}, ${wrapped.dekCiphertext})
        ON CONFLICT (workspace_id, kind, target) DO UPDATE
        SET ciphertext = EXCLUDED.ciphertext,
            dek_ciphertext = EXCLUDED.dek_ciphertext,
            rotated_at = NOW()
        RETURNING id, kind, target, created_at, rotated_at`,
  )) as Array<{
    id: string;
    kind: string;
    target: string;
    created_at: Date;
    rotated_at: Date | null;
  }>;
  const row = inserted[0];
  if (!row) throw new Error("vault insert returned no row");
  return {
    id: row.id,
    kind: row.kind,
    target: row.target,
    createdAt: row.created_at,
    rotatedAt: row.rotated_at,
  };
};

export type LoadSecretInput = {
  workspaceId: string;
  kind: string;
  target: string;
};

export const loadSecretBytes = async (
  tx: Tx,
  rawMek: Uint8Array,
  input: LoadSecretInput,
): Promise<Uint8Array | null> => {
  const rows = await tx
    .select({
      ciphertext: vaultSecrets.ciphertext,
      dekCiphertext: vaultSecrets.dekCiphertext,
    })
    .from(vaultSecrets)
    .where(
      and(
        eq(vaultSecrets.workspaceId, input.workspaceId),
        eq(vaultSecrets.kind, input.kind),
        eq(vaultSecrets.target, input.target),
      ),
    )
    .limit(1);
  const row = rows[0];
  if (!row) return null;
  const mek = await importAesKey(rawMek);
  return unwrapSecret(mek, {
    ciphertext: row.ciphertext,
    dekCiphertext: row.dekCiphertext,
  });
};

export const loadSecretString = async (
  tx: Tx,
  rawMek: Uint8Array,
  input: LoadSecretInput,
): Promise<string | null> => {
  const bytes = await loadSecretBytes(tx, rawMek, input);
  if (!bytes) return null;
  return new TextDecoder().decode(bytes);
};

export type DeleteSecretResult = {
  removed: boolean;
};

export const deleteSecret = async (tx: Tx, input: LoadSecretInput): Promise<DeleteSecretResult> => {
  const result = await tx
    .delete(vaultSecrets)
    .where(
      and(
        eq(vaultSecrets.workspaceId, input.workspaceId),
        eq(vaultSecrets.kind, input.kind),
        eq(vaultSecrets.target, input.target),
      ),
    )
    .returning({ id: vaultSecrets.id });
  return { removed: result.length > 0 };
};

export type SecretListing = {
  id: string;
  kind: string;
  target: string;
  createdAt: Date;
  rotatedAt: Date | null;
};

export const listSecrets = async (
  tx: Tx,
  workspaceId: string,
  kind?: string,
): Promise<SecretListing[]> => {
  const conditions = [eq(vaultSecrets.workspaceId, workspaceId)];
  if (kind) conditions.push(eq(vaultSecrets.kind, kind));
  const rows = await tx
    .select({
      id: vaultSecrets.id,
      kind: vaultSecrets.kind,
      target: vaultSecrets.target,
      createdAt: vaultSecrets.createdAt,
      rotatedAt: vaultSecrets.rotatedAt,
    })
    .from(vaultSecrets)
    .where(and(...conditions));
  return rows.map((r) => ({
    id: r.id,
    kind: r.kind,
    target: r.target,
    createdAt: r.createdAt,
    rotatedAt: r.rotatedAt,
  }));
};
