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
import type { DbClient, Tx } from "@getpact/db";
import { schema, withWorkspace } from "@getpact/db";
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

const aadFor = (workspaceId: string, kind: SigningKeyKind): Uint8Array =>
  new TextEncoder().encode(`keystore:v1:${workspaceId}:${kind}`);

export const createSigningKey = async (
  tx: Tx,
  opts: CreateSigningKeyOptions,
): Promise<StoredSigningKey> => {
  const pair = await generateEd25519Keypair();
  const privBytes = await exportPrivatePkcs8(pair.privateKey);
  const pubBytes = await exportPublicSpki(pair.publicKey);
  const mek = await importMek(opts.rawMek);
  const wrapped = await encryptAesGcm(mek, privBytes, aadFor(opts.workspaceId, opts.kind));

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
  const privBytes = await decryptAesGcm(
    mek,
    parse(row.privateKeyWrapped),
    aadFor(workspaceId, kind),
  );
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

export type RotateOptions = {
  workspaceId: string;
  kind: SigningKeyKind;
  rawMek: Uint8Array;
  verificationGraceSeconds?: number;
};

const DEFAULT_VERIFICATION_GRACE = 7 * 24 * 60 * 60;

export type RotateResult = {
  oldKeyId: string | null;
  newKeyId: string;
};

export const rotateSigningKey = async (tx: Tx, opts: RotateOptions): Promise<RotateResult> => {
  const grace = opts.verificationGraceSeconds ?? DEFAULT_VERIFICATION_GRACE;

  const expired = (await tx.execute(
    sql`UPDATE workspace_signing_keys
        SET valid_for_signing_until = NOW(),
            valid_for_verification_until = NOW() + (${grace} || ' seconds')::interval
        WHERE workspace_id = ${opts.workspaceId}
          AND kind = ${opts.kind}
          AND valid_for_signing_until IS NULL
        RETURNING id`,
  )) as unknown as Array<{ id: string }>;
  const oldKeyId = expired[0]?.id ?? null;

  const created = await createSigningKey(tx, {
    workspaceId: opts.workspaceId,
    kind: opts.kind,
    rawMek: opts.rawMek,
  });

  return { oldKeyId, newKeyId: created.id };
};

export type StaleSigningKey = {
  workspaceId: string;
  keyId: string;
  kind: SigningKeyKind;
  createdAt: Date;
};

export const findStaleSigningKeys = async (
  db: DbClient,
  kind: SigningKeyKind,
  maxAgeSeconds: number,
): Promise<StaleSigningKey[]> => {
  const workspaceRows = await db.select({ id: schema.workspaces.id }).from(schema.workspaces);
  const stale: StaleSigningKey[] = [];

  for (const workspace of workspaceRows) {
    const rows = (await withWorkspace(db, workspace.id, (tx) =>
      tx.execute(
        sql`SELECT id, workspace_id, kind, created_at
            FROM workspace_signing_keys
            WHERE workspace_id = ${workspace.id}
              AND kind = ${kind}
              AND valid_for_signing_until IS NULL
              AND created_at < NOW() - (${maxAgeSeconds} || ' seconds')::interval`,
      ),
    )) as unknown as Array<{
      id: string;
      workspace_id: string;
      kind: SigningKeyKind;
      created_at: Date;
    }>;

    stale.push(
      ...rows.map((r) => ({
        workspaceId: r.workspace_id,
        keyId: r.id,
        kind: r.kind,
        createdAt: r.created_at,
      })),
    );
  }

  return stale;
};

export type RotateStaleResult = {
  rotated: number;
  errors: number;
};

export const rotateStaleKeys = async (
  db: DbClient,
  rawMek: Uint8Array,
  kind: SigningKeyKind,
  maxAgeSeconds: number,
  graceSeconds?: number,
): Promise<RotateStaleResult> => {
  const stale = await findStaleSigningKeys(db, kind, maxAgeSeconds);
  let rotated = 0;
  let errors = 0;
  for (const key of stale) {
    try {
      await withWorkspace(db, key.workspaceId, (tx) =>
        rotateSigningKey(tx, {
          workspaceId: key.workspaceId,
          kind,
          rawMek,
          ...(graceSeconds !== undefined ? { verificationGraceSeconds: graceSeconds } : {}),
        }),
      );
      rotated++;
    } catch {
      errors++;
    }
  }
  return { rotated, errors };
};
