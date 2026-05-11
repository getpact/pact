import {
  type AesEnvelope,
  decryptAesGcm,
  encryptAesGcm,
  fromBase64,
  importAesKey,
  toBase64,
} from "@getpact/crypto";
import { eq, sql } from "drizzle-orm";
import { createClient } from "./client.js";
import { vaultSecrets, workspaceSigningKeys } from "./schema.js";

const IV_BYTES = 12;

const parseEnvelope = (blob: string): AesEnvelope => {
  const merged = fromBase64(blob);
  if (merged.length < IV_BYTES + 1) throw new Error("envelope too short");
  return {
    iv: merged.slice(0, IV_BYTES),
    ciphertext: merged.slice(IV_BYTES),
  };
};

const serializeEnvelope = (env: AesEnvelope): string => {
  const merged = new Uint8Array(env.iv.length + env.ciphertext.length);
  merged.set(env.iv, 0);
  merged.set(env.ciphertext, env.iv.length);
  return toBase64(merged);
};

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);

const requireEnv = (name: string): string => {
  const value = process.env[name];
  if (!value) throw new Error(`missing ${name}`);
  return value;
};

const decryptWithOptionalLegacyAad = async (
  key: CryptoKey,
  wrapped: string,
  aad: Uint8Array,
): Promise<Uint8Array> => {
  try {
    return await decryptAesGcm(key, parseEnvelope(wrapped), aad);
  } catch {
    return decryptAesGcm(key, parseEnvelope(wrapped));
  }
};

export const rewrapMek = async (opts: {
  databaseUrl: string;
  oldMek: Uint8Array;
  newMek: Uint8Array;
  newMekKeyId?: string;
  apply: boolean;
}): Promise<{ signingKeys: number; vaultSecrets: number; applied: boolean }> => {
  const oldKey = await importAesKey(opts.oldMek);
  const newKey = await importAesKey(opts.newMek);
  const db = createClient(opts.databaseUrl, { max: 1, idle_timeout: 1 });

  return db.transaction(async (tx) => {
    const signingRows = await tx
      .select({
        id: workspaceSigningKeys.id,
        workspaceId: workspaceSigningKeys.workspaceId,
        kind: workspaceSigningKeys.kind,
        wrapped: workspaceSigningKeys.privateKeyWrapped,
      })
      .from(workspaceSigningKeys);

    for (const row of signingRows) {
      const aad = bytes(`keystore:v1:${row.workspaceId}:${row.kind}`);
      const plaintext = await decryptWithOptionalLegacyAad(oldKey, row.wrapped, aad);
      const rewrapped = serializeEnvelope(await encryptAesGcm(newKey, plaintext, aad));
      if (opts.apply) {
        await tx
          .update(workspaceSigningKeys)
          .set({ privateKeyWrapped: rewrapped, mekKeyId: opts.newMekKeyId ?? null })
          .where(eq(workspaceSigningKeys.id, row.id));
      }
    }

    const vaultRows = await tx
      .select({
        id: vaultSecrets.id,
        workspaceId: vaultSecrets.workspaceId,
        kind: vaultSecrets.kind,
        target: vaultSecrets.target,
        dekCiphertext: vaultSecrets.dekCiphertext,
      })
      .from(vaultSecrets);

    for (const row of vaultRows) {
      const aad = bytes(`vault:v1:${row.workspaceId}:${row.kind}:${row.target}`);
      const dek = await decryptAesGcm(oldKey, parseEnvelope(row.dekCiphertext), aad);
      const rewrapped = serializeEnvelope(await encryptAesGcm(newKey, dek, aad));
      if (opts.apply) {
        await tx
          .update(vaultSecrets)
          .set({
            dekCiphertext: rewrapped,
            mekKeyId: opts.newMekKeyId ?? null,
            rotatedAt: sql`NOW()`,
          })
          .where(eq(vaultSecrets.id, row.id));
      }
    }

    return {
      signingKeys: signingRows.length,
      vaultSecrets: vaultRows.length,
      applied: opts.apply,
    };
  });
};

if (import.meta.url === `file://${process.argv[1]}`) {
  const newKeyId = process.env.PACT_MEK_NEW_KEY_ID;
  const result = await rewrapMek({
    databaseUrl: requireEnv("DATABASE_URL"),
    oldMek: fromBase64(requireEnv("PACT_MEK_OLD")),
    newMek: fromBase64(requireEnv("PACT_MEK_NEW")),
    ...(newKeyId ? { newMekKeyId: newKeyId } : {}),
    apply: process.env.PACT_MEK_REWRAP_APPLY === "true",
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.applied) {
    process.stdout.write("dry run only; set PACT_MEK_REWRAP_APPLY=true to persist changes\n");
  }
}
