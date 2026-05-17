import { createClient, withWorkspace } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Env, pruneReplayLog } from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const baseEnv = (overrides: Partial<Env> = {}): Env => ({
  DATABASE_URL: url ?? "postgres://unused",
  MEK: "unused",
  ISSUER_BASE_URL: "https://issuer.test/acme",
  ADMIN_AUDIENCE: "pact-admin",
  ...overrides,
});

run("admin-api scheduled prune", () => {
  const adminDb = createClient(url as string);
  const cleanup: string[] = [];

  beforeAll(async () => {
    const rows = (await adminDb.execute(
      sql`SELECT proname FROM pg_proc WHERE proname = 'prune_kbjwt_replay_log'`,
    )) as Array<{ proname: string }>;
    if (rows.length === 0) {
      throw new Error("prune_kbjwt_replay_log function not installed; run migrations");
    }
  });

  afterAll(async () => {
    while (cleanup.length > 0) {
      const id = cleanup.pop();
      if (!id) continue;
      try {
        await adminDb.delete(workspaces).where(sql`id = ${id}::uuid`);
      } catch {
        // ignore
      }
    }
  });

  const seedWorkspace = async (): Promise<string> => {
    const slug = `sched-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const [ws] = (await adminDb
      .insert(workspaces)
      .values({ slug, name: slug })
      .returning({ id: workspaces.id })) as Array<{ id: string }>;
    if (!ws) throw new Error("workspace insert failed");
    cleanup.push(ws.id);
    return ws.id;
  };

  it("uses the default 7 day window when env is unset", async () => {
    const wsId = await seedWorkspace();
    const oldJti = crypto.randomUUID();
    const recentJti = crypto.randomUUID();
    const oldHash = "11".repeat(32);
    const recentHash = "22".repeat(32);

    await withWorkspace(adminDb, wsId, (tx) =>
      tx.execute(
        sql`INSERT INTO kbjwt_replay_log (workspace_id, jti, kb_iat, sd_hash, presented_at)
            VALUES (${wsId}, ${oldJti}, ${100}, decode(${oldHash}, 'hex'), now() - interval '30 days')`,
      ),
    );
    await withWorkspace(adminDb, wsId, (tx) =>
      tx.execute(
        sql`INSERT INTO kbjwt_replay_log (workspace_id, jti, kb_iat, sd_hash, presented_at)
            VALUES (${wsId}, ${recentJti}, ${101}, decode(${recentHash}, 'hex'), now() - interval '2 hours')`,
      ),
    );

    const result = await pruneReplayLog(baseEnv());
    expect(result.days).toBe(7);
    expect(result.deleted).toBeGreaterThanOrEqual(1);

    const survivors = (await withWorkspace(adminDb, wsId, (tx) =>
      tx.execute(sql`SELECT jti::text FROM kbjwt_replay_log WHERE workspace_id = ${wsId}`),
    )) as Array<{ jti: string }>;
    const ids = survivors.map((r) => r.jti);
    expect(ids).toContain(recentJti);
    expect(ids).not.toContain(oldJti);
  });

  it("honours PACT_REPLAY_RETENTION_DAYS override", async () => {
    const wsId = await seedWorkspace();
    const midJti = crypto.randomUUID();
    const midHash = "33".repeat(32);

    await withWorkspace(adminDb, wsId, (tx) =>
      tx.execute(
        sql`INSERT INTO kbjwt_replay_log (workspace_id, jti, kb_iat, sd_hash, presented_at)
            VALUES (${wsId}, ${midJti}, ${200}, decode(${midHash}, 'hex'), now() - interval '5 days')`,
      ),
    );

    const keepResult = await pruneReplayLog(baseEnv({ PACT_REPLAY_RETENTION_DAYS: "30" }));
    expect(keepResult.days).toBe(30);
    const stillThere = (await withWorkspace(adminDb, wsId, (tx) =>
      tx.execute(
        sql`SELECT 1 FROM kbjwt_replay_log WHERE workspace_id = ${wsId} AND jti = ${midJti}`,
      ),
    )) as unknown[];
    expect(stillThere.length).toBe(1);

    const pruneResult = await pruneReplayLog(baseEnv({ PACT_REPLAY_RETENTION_DAYS: "1" }));
    expect(pruneResult.days).toBe(1);
    const gone = (await withWorkspace(adminDb, wsId, (tx) =>
      tx.execute(
        sql`SELECT 1 FROM kbjwt_replay_log WHERE workspace_id = ${wsId} AND jti = ${midJti}`,
      ),
    )) as unknown[];
    expect(gone.length).toBe(0);
  });

  it("falls back to the default when the env value is invalid", async () => {
    const result = await pruneReplayLog(baseEnv({ PACT_REPLAY_RETENTION_DAYS: "nonsense" }));
    expect(result.days).toBe(7);
  });

  it("invokes via the worker scheduled entrypoint", async () => {
    const wsId = await seedWorkspace();
    const jti = crypto.randomUUID();
    const hash = "44".repeat(32);
    await withWorkspace(adminDb, wsId, (tx) =>
      tx.execute(
        sql`INSERT INTO kbjwt_replay_log (workspace_id, jti, kb_iat, sd_hash, presented_at)
            VALUES (${wsId}, ${jti}, ${300}, decode(${hash}, 'hex'), now() - interval '14 days')`,
      ),
    );

    const worker = (await import("../worker.js")).default;
    const waited: Promise<unknown>[] = [];
    const ctx: ExecutionContext = {
      waitUntil: (p) => waited.push(p),
      passThroughOnException: () => {},
      props: {},
    } as unknown as ExecutionContext;
    const event = {
      cron: "0 3 * * *",
      type: "scheduled",
      scheduledTime: Date.now(),
    } as unknown as ScheduledEvent;

    worker.scheduled(event, baseEnv(), ctx);
    await Promise.all(waited);

    const gone = (await withWorkspace(adminDb, wsId, (tx) =>
      tx.execute(sql`SELECT 1 FROM kbjwt_replay_log WHERE workspace_id = ${wsId} AND jti = ${jti}`),
    )) as unknown[];
    expect(gone.length).toBe(0);
  });
});
