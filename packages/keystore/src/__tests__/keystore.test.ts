import { exportAesKey, generateAesKey, signEd25519, verifyEd25519 } from "@getpact/crypto";
import { createClient, type DbClient, withWorkspace } from "@getpact/db";
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
});
