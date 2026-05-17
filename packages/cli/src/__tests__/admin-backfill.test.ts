import { exportAesKey, generateAesKey, toBase64 } from "@getpact/crypto";
import { createClient, type DbClient, withWorkspace } from "@getpact/db";
import { workspaceAudiences, workspaceSigningKeys, workspaces } from "@getpact/db/schema";
import { loadActiveHmacKey, loadActiveSigningKey } from "@getpact/keystore";
import { and, eq, isNull } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runAdmin, runBackfill } from "../commands/admin.js";

const makeIo = () => {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    io: {
      out: (s: string) => out.push(s),
      err: (s: string) => err.push(s),
    },
  };
};

const url = process.env.RLS_TEST_DB ?? process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

run("admin backfill against postgres", () => {
  let db: DbClient;
  let rawMek: Uint8Array;
  let mekB64: string;
  const cleanup: string[] = [];

  beforeAll(async () => {
    db = createClient(url as string);
    const mek = await generateAesKey();
    rawMek = await exportAesKey(mek);
    mekB64 = toBase64(rawMek);
  });

  afterAll(async () => {
    while (cleanup.length > 0) {
      const id = cleanup.pop();
      if (!id) continue;
      try {
        await db.delete(workspaces).where(eq(workspaces.id, id));
      } catch {
        // ignore
      }
    }
  });

  const seedBareWorkspace = async (prefix: string): Promise<string> => {
    const slug = `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const [ws] = await db.insert(workspaces).values({ slug, name: slug }).returning();
    if (!ws) throw new Error("workspace insert failed");
    cleanup.push(ws.id);
    return ws.id;
  };

  const countAudiences = async (workspaceId: string): Promise<number> => {
    const rows = await withWorkspace(db, workspaceId, (tx) =>
      tx
        .select({ id: workspaceAudiences.id })
        .from(workspaceAudiences)
        .where(
          and(
            eq(workspaceAudiences.workspaceId, workspaceId),
            isNull(workspaceAudiences.revokedAt),
          ),
        ),
    );
    return rows.length;
  };

  const countAdapterDriveKeys = async (workspaceId: string): Promise<number> => {
    const rows = await withWorkspace(db, workspaceId, (tx) =>
      tx
        .select({ id: workspaceSigningKeys.id })
        .from(workspaceSigningKeys)
        .where(
          and(
            eq(workspaceSigningKeys.workspaceId, workspaceId),
            eq(workspaceSigningKeys.kind, "adapter-drive"),
          ),
        ),
    );
    return rows.length;
  };

  const countProvenanceKeys = async (workspaceId: string): Promise<number> => {
    const rows = await withWorkspace(db, workspaceId, (tx) =>
      tx
        .select({ id: workspaceSigningKeys.id })
        .from(workspaceSigningKeys)
        .where(
          and(
            eq(workspaceSigningKeys.workspaceId, workspaceId),
            eq(workspaceSigningKeys.kind, "provenance"),
          ),
        ),
    );
    return rows.length;
  };

  it("creates a missing adapter-drive hmac key when --what keys", async () => {
    const wsId = await seedBareWorkspace("bk-keys");
    expect(await countAdapterDriveKeys(wsId)).toBe(0);

    const summary = await runBackfill({
      databaseUrl: url as string,
      rawMek,
      workspaceId: wsId,
      what: "keys",
      dryRun: false,
    });
    expect(summary.scanned).toBe(1);
    expect(summary.hmacCreated).toBe(1);
    expect(summary.actions[0]?.hmacCreated).toBe(true);

    const loaded = await withWorkspace(db, wsId, (tx) =>
      loadActiveHmacKey(tx, wsId, "adapter-drive", rawMek),
    );
    expect(loaded.keyBytes.length).toBe(32);
    expect(await countAdapterDriveKeys(wsId)).toBe(1);
  });

  it("creates a missing provenance signing key when --what keys", async () => {
    const wsId = await seedBareWorkspace("bk-prov");
    expect(await countProvenanceKeys(wsId)).toBe(0);

    const summary = await runBackfill({
      databaseUrl: url as string,
      rawMek,
      workspaceId: wsId,
      what: "keys",
      dryRun: false,
    });
    expect(summary.scanned).toBe(1);
    expect(summary.provenanceCreated).toBe(1);
    expect(summary.actions[0]?.provenanceCreated).toBe(true);

    const loaded = await withWorkspace(db, wsId, (tx) =>
      loadActiveSigningKey(tx, wsId, "provenance", rawMek),
    );
    expect(loaded.id).toBeDefined();
    expect(await countProvenanceKeys(wsId)).toBe(1);
  });

  it("is idempotent on re-run", async () => {
    const wsId = await seedBareWorkspace("bk-idem");

    const first = await runBackfill({
      databaseUrl: url as string,
      rawMek,
      workspaceId: wsId,
      what: "all",
      dryRun: false,
    });
    expect(first.hmacCreated).toBe(1);
    expect(first.provenanceCreated).toBe(1);
    expect(first.audiencesInserted).toBeGreaterThan(0);

    const second = await runBackfill({
      databaseUrl: url as string,
      rawMek,
      workspaceId: wsId,
      what: "all",
      dryRun: false,
    });
    expect(second.scanned).toBe(1);
    expect(second.hmacCreated).toBe(0);
    expect(second.provenanceCreated).toBe(0);
    expect(second.audiencesInserted).toBe(0);
    expect(second.actions[0]?.hmacCreated).toBe(false);
    expect(second.actions[0]?.provenanceCreated).toBe(false);
    expect(second.actions[0]?.audiencesInserted).toEqual([]);
  });

  it("inserts missing default audiences when --what audiences", async () => {
    const wsId = await seedBareWorkspace("bk-aud");
    expect(await countAudiences(wsId)).toBe(0);

    const summary = await runBackfill({
      databaseUrl: url as string,
      rawMek,
      workspaceId: wsId,
      what: "audiences",
      dryRun: false,
    });
    expect(summary.scanned).toBe(1);
    expect(summary.audiencesInserted).toBeGreaterThan(0);
    expect(summary.hmacCreated).toBe(0);
    expect(summary.provenanceCreated).toBe(0);

    const count = await countAudiences(wsId);
    expect(count).toBe(summary.audiencesInserted);
    expect(count).toBeGreaterThanOrEqual(5);
  });

  it("dry-run reports planned actions without changing the database", async () => {
    const wsId = await seedBareWorkspace("bk-dry");
    expect(await countAudiences(wsId)).toBe(0);
    expect(await countAdapterDriveKeys(wsId)).toBe(0);
    expect(await countProvenanceKeys(wsId)).toBe(0);

    const summary = await runBackfill({
      databaseUrl: url as string,
      rawMek,
      workspaceId: wsId,
      what: "all",
      dryRun: true,
    });
    expect(summary.hmacCreated).toBe(1);
    expect(summary.provenanceCreated).toBe(1);
    expect(summary.audiencesInserted).toBeGreaterThan(0);

    expect(await countAudiences(wsId)).toBe(0);
    expect(await countAdapterDriveKeys(wsId)).toBe(0);
    expect(await countProvenanceKeys(wsId)).toBe(0);
  });

  it("runs end-to-end via the CLI entry point and prints a summary", async () => {
    const wsId = await seedBareWorkspace("bk-cli");
    const { io, out, err } = makeIo();
    const res = await runAdmin(["backfill", "--workspace", wsId, "--what", "all"], io, {
      DATABASE_URL: url as string,
      MEK: mekB64,
    } as NodeJS.ProcessEnv);
    expect(res.exitCode).toBe(0);
    expect(err.join("")).toBe("");
    const stdout = out.join("");
    expect(stdout).toContain(`(${wsId})`);
    expect(stdout).toContain("create adapter-drive hmac key");
    expect(stdout).toContain("create provenance signing key");
    expect(stdout).toContain("insert audiences");
    expect(await countAdapterDriveKeys(wsId)).toBe(1);
    expect(await countProvenanceKeys(wsId)).toBe(1);
    expect(await countAudiences(wsId)).toBeGreaterThanOrEqual(5);
  });
});

describe("admin backfill flag handling", () => {
  it("rejects an invalid --what value before opening a connection", async () => {
    const { io, err } = makeIo();
    const res = await runAdmin(["backfill", "--what", "nope"], io, {
      DATABASE_URL: "postgres://disabled.invalid/none",
      MEK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    } as NodeJS.ProcessEnv);
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("--what");
  });

  it("exits 1 when MEK is missing", async () => {
    const { io, err } = makeIo();
    const res = await runAdmin(["backfill"], io, {
      DATABASE_URL: "postgres://disabled.invalid/none",
    } as NodeJS.ProcessEnv);
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("MEK");
  });

  it("usage includes the new backfill subcommand", async () => {
    const { io, err } = makeIo();
    const res = await runAdmin(["nope"], io, {} as NodeJS.ProcessEnv);
    expect(res.exitCode).toBe(1);
    const stderr = err.join("");
    expect(stderr).toContain("admin backfill");
    expect(stderr).toContain("admin prune-replay-log");
  });
});
