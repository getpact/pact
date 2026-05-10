import {
  encryptAesGcm,
  exportAesKey,
  exportPrivatePkcs8,
  exportPublicSpki,
  generateAesKey,
  generateEd25519Keypair,
  importAesKey,
  signEd25519,
  toBase64,
  verifyEd25519,
} from "@getpact/crypto";
import { createClient, type DbClient, schema, withWorkspace } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createSigningKey, listVerifyingKeys, loadActiveSigningKey } from "../index.js";

const url = process.env.RLS_TEST_DB;
const run = url ? describe : describe.skip;

run("keystore", () => {
  let db: DbClient;
  let workspaceId: string;
  let rawMek: Uint8Array;

  beforeAll(async () => {
    db = createClient(url as string);
    const [ws] = await db
      .insert(workspaces)
      .values({ slug: `ks-${Date.now()}`, name: "KS" })
      .returning();
    if (!ws) throw new Error("workspace insert failed");
    workspaceId = ws.id;
    const mek = await generateAesKey();
    rawMek = await exportAesKey(mek);
  });

  afterAll(async () => {
    await db.delete(workspaces).where(eq(workspaces.id, workspaceId));
  });

  it("creates and loads an active jwt signing key", async () => {
    const created = await withWorkspace(db, workspaceId, (tx) =>
      createSigningKey(tx, { workspaceId, kind: "jwt", rawMek }),
    );
    expect(created.id).toBeDefined();

    const active = await withWorkspace(db, workspaceId, (tx) =>
      loadActiveSigningKey(tx, workspaceId, "jwt", rawMek),
    );
    expect(active.id).toBe(created.id);

    const data = new TextEncoder().encode("test payload");
    const sig = await signEd25519(active.privateKey, data);
    const ok = await verifyEd25519(active.publicKey, data, sig);
    expect(ok).toBe(true);
  });

  it("lists verifying keys including past versions", async () => {
    await withWorkspace(db, workspaceId, (tx) =>
      createSigningKey(tx, { workspaceId, kind: "audit", rawMek }),
    );
    await withWorkspace(db, workspaceId, (tx) =>
      createSigningKey(tx, { workspaceId, kind: "audit", rawMek }),
    );

    const keys = await withWorkspace(db, workspaceId, (tx) =>
      listVerifyingKeys(tx, workspaceId, "audit"),
    );
    expect(keys.length).toBe(2);
    for (const k of keys) {
      expect(k.publicKey).toBeDefined();
    }
  });

  it("isolates keys per kind", async () => {
    const jwt = await withWorkspace(db, workspaceId, (tx) =>
      loadActiveSigningKey(tx, workspaceId, "jwt", rawMek),
    );
    const audit = await withWorkspace(db, workspaceId, (tx) =>
      loadActiveSigningKey(tx, workspaceId, "audit", rawMek),
    );
    expect(jwt.id).not.toBe(audit.id);
  });

  it("loads and rewraps legacy keys encrypted without AAD", async () => {
    const pair = await generateEd25519Keypair();
    const privBytes = await exportPrivatePkcs8(pair.privateKey);
    const pubBytes = await exportPublicSpki(pair.publicKey);
    const mek = await importAesKey(rawMek);
    const wrapped = await encryptAesGcm(mek, privBytes);
    const merged = new Uint8Array(wrapped.iv.length + wrapped.ciphertext.length);
    merged.set(wrapped.iv, 0);
    merged.set(wrapped.ciphertext, wrapped.iv.length);

    const [legacy] = await withWorkspace(db, workspaceId, (tx) =>
      tx
        .insert(schema.workspaceSigningKeys)
        .values({
          workspaceId,
          kind: "jwt",
          publicKeySpki: toBase64(pubBytes),
          privateKeyWrapped: toBase64(merged),
        })
        .returning({ id: schema.workspaceSigningKeys.id }),
    );
    if (!legacy) throw new Error("legacy key insert failed");

    const active = await withWorkspace(db, workspaceId, (tx) =>
      loadActiveSigningKey(tx, workspaceId, "jwt", rawMek),
    );
    expect(active.id).toBe(legacy.id);

    await withWorkspace(db, workspaceId, async (tx) => {
      const [row] = await tx
        .select({ wrapped: schema.workspaceSigningKeys.privateKeyWrapped })
        .from(schema.workspaceSigningKeys)
        .where(eq(schema.workspaceSigningKeys.id, legacy.id))
        .limit(1);
      expect(row?.wrapped).not.toBe(toBase64(merged));
    });
  });
});

import { sql } from "drizzle-orm";
import { findStaleSigningKeys, rotateSigningKey, rotateStaleKeys } from "../index.js";

const adminUrl = process.env.DATABASE_URL;
const rotationRun = adminUrl ? describe : describe.skip;

rotationRun("keystore rotation", () => {
  let db: DbClient;
  let workspaceId: string;
  let rawMek: Uint8Array;

  beforeAll(async () => {
    db = createClient(adminUrl as string);
    const [ws] = await db
      .insert(workspaces)
      .values({ slug: `rot-${Date.now()}`, name: "Rot" })
      .returning();
    if (!ws) throw new Error("workspace insert failed");
    workspaceId = ws.id;
    const mek = await generateAesKey();
    rawMek = await exportAesKey(mek);

    await withWorkspace(db, workspaceId, (tx) =>
      createSigningKey(tx, { workspaceId, kind: "jwt", rawMek }),
    );
  });

  afterAll(async () => {
    await db.delete(workspaces).where(eq(workspaces.id, workspaceId));
  });

  it("rotateSigningKey marks old key inactive and inserts a new active one", async () => {
    const before = await withWorkspace(db, workspaceId, (tx) =>
      loadActiveSigningKey(tx, workspaceId, "jwt", rawMek),
    );

    const result = await withWorkspace(db, workspaceId, (tx) =>
      rotateSigningKey(tx, { workspaceId, kind: "jwt", rawMek }),
    );
    expect(result.oldKeyId).toBe(before.id);
    expect(result.newKeyId).not.toBe(before.id);

    const after = await withWorkspace(db, workspaceId, (tx) =>
      loadActiveSigningKey(tx, workspaceId, "jwt", rawMek),
    );
    expect(after.id).toBe(result.newKeyId);

    const verifying = await withWorkspace(db, workspaceId, (tx) =>
      listVerifyingKeys(tx, workspaceId, "jwt"),
    );
    const ids = verifying.map((k) => k.id);
    expect(ids).toContain(result.oldKeyId);
    expect(ids).toContain(result.newKeyId);
  });

  it("findStaleSigningKeys honors maxAgeSeconds", async () => {
    await db.execute(
      sql`UPDATE workspace_signing_keys
          SET created_at = NOW() - INTERVAL '100 days'
          WHERE workspace_id = ${workspaceId} AND kind = 'jwt' AND valid_for_signing_until IS NULL`,
    );
    const stale = await findStaleSigningKeys(db, "jwt", 90 * 24 * 60 * 60);
    expect(stale.some((k) => k.workspaceId === workspaceId)).toBe(true);
  });

  it("rotateStaleKeys rotates aged keys", async () => {
    await db.execute(
      sql`UPDATE workspace_signing_keys
          SET created_at = NOW() - INTERVAL '100 days'
          WHERE workspace_id = ${workspaceId} AND kind = 'jwt' AND valid_for_signing_until IS NULL`,
    );
    const result = await rotateStaleKeys(db, rawMek, "jwt", 90 * 24 * 60 * 60, 60);
    expect(result.rotated).toBeGreaterThan(0);
    expect(result.errors).toBe(0);
  });
});
