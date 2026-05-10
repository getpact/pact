import {
  type AesEnvelope,
  decryptAesGcm,
  encryptAesGcm,
  exportPrivatePkcs8,
  exportPublicSpki,
  fromBase64,
  generateEd25519Keypair,
  importAesKey,
  importPrivatePkcs8,
  importPublicSpki,
  toBase64,
} from "@getpact/crypto";
import type { Tx } from "@getpact/db";
import { schema } from "@getpact/db";
import { and, asc, desc, eq, gt, isNull, or, sql } from "drizzle-orm";

export type SigningKeyKind = "jwt" | "audit";

const IV_BYTES = 12;

const serialize = (env: AesEnvelope): string => {
  const merged = new Uint8Array(env.iv.length + env.ciphertext.length);
  merged.set(env.iv, 0);
  merged.set(env.ciphertext, env.iv.length);
  return toBase64(merged);
};

const parse = (blob: string): AesEnvelope => {
  const merged = fromBase64(blob);
  if (merged.length < IV_BYTES + 1) throw new Error("envelope too short");
  return { iv: merged.slice(0, IV_BYTES), ciphertext: merged.slice(IV_BYTES) };
};

const importMek = async (rawMek: Uint8Array): Promise<CryptoKey> => importAesKey(rawMek);

export type CreateSigningKeyOptions = {
  workspaceId: string;
  kind: SigningKeyKind;
  rawMek: Uint8Array;
};

export type StoredSigningKey = {
  id: string;
  publicSpki: string;
};

export const createSigningKey = async (
  tx: Tx,
  opts: CreateSigningKeyOptions,
): Promise<StoredSigningKey> => {
  const pair = await generateEd25519Keypair();
  const privBytes = await exportPrivatePkcs8(pair.privateKey);
  const pubBytes = await exportPublicSpki(pair.publicKey);
  const mek = await importMek(opts.rawMek);
  const wrapped = await encryptAesGcm(mek, privBytes);

  const inserted = (await tx.execute(
    sql`INSERT INTO workspace_signing_keys (workspace_id, kind, public_key_spki, private_key_wrapped)
        VALUES (${opts.workspaceId}, ${opts.kind}, ${toBase64(pubBytes)}, ${serialize(wrapped)})
        RETURNING id`,
  )) as Array<{ id: string }>;

  const id = inserted[0]?.id;
  if (!id) throw new Error("signing key insert returned no id");
  return { id, publicSpki: toBase64(pubBytes) };
};

export type ActiveSigningKey = {
  id: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
};

export const loadActiveSigningKey = async (
  tx: Tx,
  workspaceId: string,
  kind: SigningKeyKind,
  rawMek: Uint8Array,
): Promise<ActiveSigningKey> => {
  const rows = await tx
    .select()
    .from(schema.workspaceSigningKeys)
    .where(
      and(
        eq(schema.workspaceSigningKeys.workspaceId, workspaceId),
        eq(schema.workspaceSigningKeys.kind, kind),
        or(
          isNull(schema.workspaceSigningKeys.validForSigningUntil),
          gt(schema.workspaceSigningKeys.validForSigningUntil, sql`NOW()`),
        ),
      ),
    )
    .orderBy(desc(schema.workspaceSigningKeys.createdAt))
    .limit(1);

  const row = rows[0];
  if (!row) throw new Error(`no active ${kind} signing key for workspace ${workspaceId}`);

  const mek = await importMek(rawMek);
  const privBytes = await decryptAesGcm(mek, parse(row.privateKeyWrapped));
  const pubBytes = fromBase64(row.publicKeySpki);
  const privateKey = await importPrivatePkcs8(privBytes);
  const publicKey = await importPublicSpki(pubBytes);
  return { id: row.id, privateKey, publicKey };
};

export type VerifyingKey = {
  id: string;
  publicKey: CryptoKey;
};

export const listVerifyingKeys = async (
  tx: Tx,
  workspaceId: string,
  kind: SigningKeyKind,
): Promise<VerifyingKey[]> => {
  const rows = await tx
    .select()
    .from(schema.workspaceSigningKeys)
    .where(
      and(
        eq(schema.workspaceSigningKeys.workspaceId, workspaceId),
        eq(schema.workspaceSigningKeys.kind, kind),
        or(
          isNull(schema.workspaceSigningKeys.validForVerificationUntil),
          gt(schema.workspaceSigningKeys.validForVerificationUntil, sql`NOW()`),
        ),
      ),
    )
    .orderBy(asc(schema.workspaceSigningKeys.createdAt));

  return Promise.all(
    rows.map(async (row) => ({
      id: row.id,
      publicKey: await importPublicSpki(fromBase64(row.publicKeySpki)),
    })),
  );
};
