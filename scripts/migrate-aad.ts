#!/usr/bin/env -S node --experimental-strip-types
import {
  type AesEnvelope,
  decryptAesGcm,
  encryptAesGcm,
  fromBase64,
  importAesKey,
  toBase64,
} from "../packages/crypto/src/index.ts";
import { eq } from "../packages/db/node_modules/drizzle-orm/index.js";
import { createClient } from "../packages/db/src/client.ts";
import { workspaceSigningKeys } from "../packages/db/src/schema.ts";

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

const aadFor = (workspaceId: string, kind: string): Uint8Array =>
  new TextEncoder().encode(`keystore:v1:${workspaceId}:${kind}`);

const requireEnv = (name: string): string => {
  const value = process.env[name];
  if (!value) throw new Error(`missing ${name}`);
  return value;
};

const flagEnabled = (name: string): boolean => {
  const v = process.env[name];
  if (!v) return false;
  const lower = v.toLowerCase();
  return lower === "1" || lower === "true" || lower === "yes" || lower === "on";
};

type RowSummary = {
  id: string;
  workspaceId: string;
  kind: string;
  status: "ok" | "rewrapped" | "tampered" | "skipped";
  detail?: string;
};

const log = (entry: RowSummary): void => {
  process.stdout.write(`${JSON.stringify(entry)}\n`);
};

export const migrateAad = async (opts: {
  databaseUrl: string;
  rawMek: Uint8Array;
  apply: boolean;
}): Promise<{ total: number; ok: number; rewrapped: number; tampered: number }> => {
  const mek = await importAesKey(opts.rawMek);
  const db = createClient(opts.databaseUrl, { max: 1, idle_timeout: 1 });

  let total = 0;
  let ok = 0;
  let rewrapped = 0;
  let tampered = 0;

  const rows = await db
    .select({
      id: workspaceSigningKeys.id,
      workspaceId: workspaceSigningKeys.workspaceId,
      kind: workspaceSigningKeys.kind,
      wrapped: workspaceSigningKeys.privateKeyWrapped,
    })
    .from(workspaceSigningKeys);

  for (const row of rows) {
    total += 1;
    const aad = aadFor(row.workspaceId, row.kind);
    const envelope = parseEnvelope(row.wrapped);

    try {
      await decryptAesGcm(mek, envelope, aad);
      ok += 1;
      log({ id: row.id, workspaceId: row.workspaceId, kind: row.kind, status: "ok" });
      continue;
    } catch {
      // fall through to legacy path
    }

    let plaintext: Uint8Array;
    try {
      plaintext = await decryptAesGcm(mek, envelope);
    } catch (err) {
      tampered += 1;
      const detail = err instanceof Error ? err.message : String(err);
      log({
        id: row.id,
        workspaceId: row.workspaceId,
        kind: row.kind,
        status: "tampered",
        detail,
      });
      continue;
    }

    if (!opts.apply) {
      rewrapped += 1;
      log({
        id: row.id,
        workspaceId: row.workspaceId,
        kind: row.kind,
        status: "skipped",
        detail: "dry run",
      });
      continue;
    }

    const newEnvelope = await encryptAesGcm(mek, plaintext, aad);
    await db
      .update(workspaceSigningKeys)
      .set({ privateKeyWrapped: serializeEnvelope(newEnvelope) })
      .where(eq(workspaceSigningKeys.id, row.id));
    rewrapped += 1;
    log({ id: row.id, workspaceId: row.workspaceId, kind: row.kind, status: "rewrapped" });
  }

  return { total, ok, rewrapped, tampered };
};

if (import.meta.url === `file://${process.argv[1]}`) {
  if (!flagEnabled("KEYSTORE_LEGACY_REWRAP")) {
    process.stderr.write(
      "[migrate-aad] refusing to run without KEYSTORE_LEGACY_REWRAP=1; " +
        "this flag must be set explicitly so callers acknowledge the legacy path\n",
    );
    process.exit(2);
  }

  const apply = flagEnabled("PACT_MIGRATE_AAD_APPLY");
  const result = await migrateAad({
    databaseUrl: requireEnv("DATABASE_URL"),
    rawMek: fromBase64(requireEnv("PACT_MEK")),
    apply,
  });

  process.stdout.write(`${JSON.stringify({ summary: result, applied: apply })}\n`);
  if (!apply) {
    process.stdout.write(
      "dry run only; set PACT_MIGRATE_AAD_APPLY=1 to persist rewraps to the database\n",
    );
  }
  if (result.tampered > 0) {
    process.exit(1);
  }
}
