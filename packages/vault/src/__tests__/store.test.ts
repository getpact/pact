import { exportAesKey, generateAesKey } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import {
  deleteSecret,
  listSecrets,
  loadSecretBytes,
  loadSecretString,
  storeSecret,
} from "../index.js";

const url = process.env.RLS_TEST_DB;
const run = url ? describe : describe.skip;

run("vault store", () => {
  const adminDb = createClient(url as string);
  const cleanup: string[] = [];

  afterEach(async () => {
    while (cleanup.length > 0) {
      const id = cleanup.pop();
      if (!id) continue;
      try {
        await adminDb.delete(workspaces).where(eq(workspaces.id, id));
      } catch {
        // ignore
      }
    }
  });

  const setup = async () => {
    const [ws] = await adminDb
      .insert(workspaces)
      .values({
        slug: `vault-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        name: "Vault",
      })
      .returning();
    if (!ws) throw new Error("workspace insert failed");
    cleanup.push(ws.id);
    const mek = await generateAesKey();
    const rawMek = await exportAesKey(mek);
    return { workspaceId: ws.id, rawMek };
  };

  it("stores and loads a secret as bytes", async () => {
    const { workspaceId, rawMek } = await setup();
    await withWorkspace(adminDb, workspaceId, (tx) =>
      storeSecret(tx, rawMek, {
        workspaceId,
        kind: "slack",
        target: "user-token",
        plaintext: "xoxp-12345",
      }),
    );
    const out = await withWorkspace(adminDb, workspaceId, (tx) =>
      loadSecretString(tx, rawMek, { workspaceId, kind: "slack", target: "user-token" }),
    );
    expect(out).toBe("xoxp-12345");
  });

  it("returns null when secret missing", async () => {
    const { workspaceId, rawMek } = await setup();
    const out = await withWorkspace(adminDb, workspaceId, (tx) =>
      loadSecretBytes(tx, rawMek, { workspaceId, kind: "slack", target: "missing" }),
    );
    expect(out).toBeNull();
  });

  it("rotates a secret on conflict and updates rotated_at", async () => {
    const { workspaceId, rawMek } = await setup();
    const first = await withWorkspace(adminDb, workspaceId, (tx) =>
      storeSecret(tx, rawMek, {
        workspaceId,
        kind: "slack",
        target: "user-token",
        plaintext: "v1",
      }),
    );
    expect(first.rotatedAt).toBeNull();

    const second = await withWorkspace(adminDb, workspaceId, (tx) =>
      storeSecret(tx, rawMek, {
        workspaceId,
        kind: "slack",
        target: "user-token",
        plaintext: "v2",
      }),
    );
    expect(second.id).toBe(first.id);
    expect(second.rotatedAt).not.toBeNull();

    const out = await withWorkspace(adminDb, workspaceId, (tx) =>
      loadSecretString(tx, rawMek, { workspaceId, kind: "slack", target: "user-token" }),
    );
    expect(out).toBe("v2");
  });

  it("lists and deletes secrets", async () => {
    const { workspaceId, rawMek } = await setup();
    await withWorkspace(adminDb, workspaceId, (tx) =>
      storeSecret(tx, rawMek, { workspaceId, kind: "slack", target: "a", plaintext: "x" }),
    );
    await withWorkspace(adminDb, workspaceId, (tx) =>
      storeSecret(tx, rawMek, { workspaceId, kind: "slack", target: "b", plaintext: "y" }),
    );
    await withWorkspace(adminDb, workspaceId, (tx) =>
      storeSecret(tx, rawMek, { workspaceId, kind: "drive", target: "c", plaintext: "z" }),
    );

    const slackOnly = await withWorkspace(adminDb, workspaceId, (tx) =>
      listSecrets(tx, workspaceId, "slack"),
    );
    expect(slackOnly.map((s) => s.target).sort()).toEqual(["a", "b"]);

    const all = await withWorkspace(adminDb, workspaceId, (tx) => listSecrets(tx, workspaceId));
    expect(all.length).toBe(3);

    const removed = await withWorkspace(adminDb, workspaceId, (tx) =>
      deleteSecret(tx, { workspaceId, kind: "slack", target: "a" }),
    );
    expect(removed.removed).toBe(true);

    const after = await withWorkspace(adminDb, workspaceId, (tx) => listSecrets(tx, workspaceId));
    expect(after.length).toBe(2);
  });

  it("isolates by kind and target uniqueness scope", async () => {
    const { workspaceId, rawMek } = await setup();
    await withWorkspace(adminDb, workspaceId, (tx) =>
      storeSecret(tx, rawMek, {
        workspaceId,
        kind: "slack",
        target: "user-token",
        plaintext: "slackval",
      }),
    );
    await withWorkspace(adminDb, workspaceId, (tx) =>
      storeSecret(tx, rawMek, {
        workspaceId,
        kind: "drive",
        target: "user-token",
        plaintext: "driveval",
      }),
    );
    const slack = await withWorkspace(adminDb, workspaceId, (tx) =>
      loadSecretString(tx, rawMek, { workspaceId, kind: "slack", target: "user-token" }),
    );
    const drive = await withWorkspace(adminDb, workspaceId, (tx) =>
      loadSecretString(tx, rawMek, { workspaceId, kind: "drive", target: "user-token" }),
    );
    expect(slack).toBe("slackval");
    expect(drive).toBe("driveval");
  });
});
