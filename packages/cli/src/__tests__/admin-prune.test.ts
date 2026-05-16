import { createClient, type DbClient, withWorkspace } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseDuration, parseFlags, runAdmin } from "../commands/admin.js";

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

describe("parseFlags", () => {
  it("collects positionals, values, and bare booleans", () => {
    const p = parseFlags(["prune-replay-log", "--older-than", "7d", "--apply"]);
    expect(p.positional).toEqual(["prune-replay-log"]);
    expect(p.flags.get("older-than")).toBe("7d");
    expect(p.booleans.has("apply")).toBe(true);
  });
});

describe("parseDuration", () => {
  it("renders SQL-friendly intervals for each unit", () => {
    expect(parseDuration("30s")).toBe("30 seconds");
    expect(parseDuration("15m")).toBe("15 minutes");
    expect(parseDuration("24h")).toBe("24 hours");
    expect(parseDuration("7d")).toBe("7 days");
    expect(parseDuration("2w")).toBe("14 days");
    expect(parseDuration(" 7d ")).toBe("7 days");
  });

  it("rejects empty, zero, negative, or malformed input", () => {
    expect(() => parseDuration("")).toThrow();
    expect(() => parseDuration("0d")).toThrow();
    expect(() => parseDuration("-1d")).toThrow();
    expect(() => parseDuration("7")).toThrow();
    expect(() => parseDuration("7y")).toThrow();
    expect(() => parseDuration("abc")).toThrow();
  });
});

describe("runAdmin dispatch", () => {
  it("prints usage on unknown subcommand", async () => {
    const { io, err } = makeIo();
    const res = await runAdmin(["nope"], io, {} as NodeJS.ProcessEnv);
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("usage: pact admin prune-replay-log");
  });

  it("exits 1 when DATABASE_URL is missing", async () => {
    const { io, err } = makeIo();
    const res = await runAdmin(["prune-replay-log"], io, {} as NodeJS.ProcessEnv);
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("DATABASE_URL");
  });

  it("rejects an invalid --older-than before opening any connection", async () => {
    const { io, err } = makeIo();
    const res = await runAdmin(["prune-replay-log", "--older-than", "nope"], io, {
      DATABASE_URL: "postgres://disabled.invalid/none",
    } as NodeJS.ProcessEnv);
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("--older-than");
  });
});

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

run("prune_kbjwt_replay_log against postgres", () => {
  const db: DbClient = createClient(url as string);
  const cleanup: string[] = [];

  beforeAll(async () => {
    const rows = (await db.execute(
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
        await db.delete(workspaces).where(sql`id = ${id}::uuid`);
      } catch {
        // ignore
      }
    }
  });

  const seedWorkspace = async (): Promise<string> => {
    const slug = `prune-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const [ws] = (await db
      .insert(workspaces)
      .values({ slug, name: slug })
      .returning({ id: workspaces.id })) as Array<{ id: string }>;
    if (!ws) throw new Error("workspace insert failed");
    cleanup.push(ws.id);
    return ws.id;
  };

  it("deletes rows older than the window and keeps recent ones", async () => {
    const wsId = await seedWorkspace();
    const oldJti = crypto.randomUUID();
    const recentJti = crypto.randomUUID();
    const oldHashHex = "ab".repeat(32);
    const recentHashHex = "cd".repeat(32);

    await withWorkspace(db, wsId, (tx) =>
      tx.execute(
        sql`INSERT INTO kbjwt_replay_log (workspace_id, jti, kb_iat, sd_hash, presented_at)
            VALUES (${wsId}, ${oldJti}, ${1}, decode(${oldHashHex}, 'hex'), now() - interval '30 days')`,
      ),
    );
    await withWorkspace(db, wsId, (tx) =>
      tx.execute(
        sql`INSERT INTO kbjwt_replay_log (workspace_id, jti, kb_iat, sd_hash, presented_at)
            VALUES (${wsId}, ${recentJti}, ${2}, decode(${recentHashHex}, 'hex'), now() - interval '1 hour')`,
      ),
    );

    const deletedRows = (await db.execute(
      sql`SELECT prune_kbjwt_replay_log('7 days'::interval) AS n`,
    )) as Array<{ n: number | string | bigint }>;
    const deleted = Number(deletedRows[0]?.n ?? 0);
    expect(deleted).toBeGreaterThanOrEqual(1);

    const survivors = (await withWorkspace(db, wsId, (tx) =>
      tx.execute(sql`SELECT jti::text FROM kbjwt_replay_log WHERE workspace_id = ${wsId}`),
    )) as Array<{ jti: string }>;
    const ids = survivors.map((r) => r.jti);
    expect(ids).toContain(recentJti);
    expect(ids).not.toContain(oldJti);
  });

  it("rejects a non-positive interval", async () => {
    await expect(
      db.execute(sql`SELECT prune_kbjwt_replay_log('0 seconds'::interval)`),
    ).rejects.toThrow();
  });

  it("runs cross-workspace from the CLI entry point", async () => {
    const wsA = await seedWorkspace();
    const wsB = await seedWorkspace();
    const oldA = crypto.randomUUID();
    const oldB = crypto.randomUUID();
    const hash = "ef".repeat(32);

    await withWorkspace(db, wsA, (tx) =>
      tx.execute(
        sql`INSERT INTO kbjwt_replay_log (workspace_id, jti, kb_iat, sd_hash, presented_at)
            VALUES (${wsA}, ${oldA}, ${10}, decode(${hash}, 'hex'), now() - interval '40 days')`,
      ),
    );
    await withWorkspace(db, wsB, (tx) =>
      tx.execute(
        sql`INSERT INTO kbjwt_replay_log (workspace_id, jti, kb_iat, sd_hash, presented_at)
            VALUES (${wsB}, ${oldB}, ${11}, decode(${hash}, 'hex'), now() - interval '40 days')`,
      ),
    );

    const { io, out, err } = makeIo();
    const res = await runAdmin(["prune-replay-log", "--older-than", "7d"], io, {
      DATABASE_URL: url as string,
    } as NodeJS.ProcessEnv);
    expect(res.exitCode).toBe(0);
    expect(err.join("")).toBe("");
    expect(out.join("")).toMatch(/pruned \d+ kbjwt_replay_log row/);

    const remainingA = (await withWorkspace(db, wsA, (tx) =>
      tx.execute(sql`SELECT 1 FROM kbjwt_replay_log WHERE workspace_id = ${wsA} AND jti = ${oldA}`),
    )) as unknown[];
    const remainingB = (await withWorkspace(db, wsB, (tx) =>
      tx.execute(sql`SELECT 1 FROM kbjwt_replay_log WHERE workspace_id = ${wsB} AND jti = ${oldB}`),
    )) as unknown[];
    expect(remainingA.length).toBe(0);
    expect(remainingB.length).toBe(0);
  });
});
