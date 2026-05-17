import { DEFAULT_AUDIENCES } from "@getpact/core";
import { fromBase64 } from "@getpact/crypto";
import { createClient, type DbClient, schema, withWorkspace } from "@getpact/db";
import {
  createHmacKey,
  createSigningKey,
  loadActiveHmacKey,
  loadActiveSigningKey,
} from "@getpact/keystore";
import { and, eq, isNull, sql } from "drizzle-orm";

const DEFAULT_OLDER_THAN = "7d";
const ADAPTER_DRIVE_KIND = "adapter-drive" as const;
const PROVENANCE_KIND = "provenance" as const;

export type ParsedFlags = {
  positional: string[];
  flags: Map<string, string>;
  booleans: Set<string>;
};

export const parseFlags = (argv: readonly string[]): ParsedFlags => {
  const positional: string[] = [];
  const flags = new Map<string, string>();
  const booleans = new Set<string>();
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i] ?? "";
    if (a.startsWith("--")) {
      const name = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags.set(name, next);
        i += 1;
      } else {
        booleans.add(name);
      }
      continue;
    }
    positional.push(a);
  }
  return { positional, flags, booleans };
};

const DURATION_RE = /^(\d+)\s*(s|m|h|d|w)$/i;

export const parseDuration = (input: string): string => {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    throw new Error("--older-than must not be empty");
  }
  const match = DURATION_RE.exec(trimmed);
  if (!match) {
    throw new Error(`invalid --older-than '${input}'; use a value like 7d, 24h, 30m, 1w`);
  }
  const amount = Number.parseInt(match[1] ?? "0", 10);
  if (!Number.isFinite(amount) || amount <= 0) {
    throw new Error("--older-than must be a positive integer with a unit");
  }
  const MAX_DAYS = 3650;
  const unit = (match[2] ?? "").toLowerCase();
  const days = (() => {
    switch (unit) {
      case "s":
        return amount / 86400;
      case "m":
        return amount / 1440;
      case "h":
        return amount / 24;
      case "d":
        return amount;
      case "w":
        return amount * 7;
      default:
        throw new Error(`invalid --older-than unit '${unit}'`);
    }
  })();
  if (days > MAX_DAYS) {
    throw new Error(`--older-than '${input}' exceeds maximum of ${MAX_DAYS} days`);
  }
  switch (unit) {
    case "s":
      return `${amount} seconds`;
    case "m":
      return `${amount} minutes`;
    case "h":
      return `${amount} hours`;
    case "d":
      return `${amount} days`;
    case "w":
      return `${amount * 7} days`;
    default:
      throw new Error(`invalid --older-than unit '${unit}'`);
  }
};

const databaseUrl = (env: NodeJS.ProcessEnv): string => {
  const url = env.DATABASE_URL;
  if (!url || url.length === 0) {
    throw new Error("missing DATABASE_URL");
  }
  return url;
};

export type PruneResult = { deleted: number; olderThan: string };

export const prunePactReplayLog = async (url: string, olderThan: string): Promise<PruneResult> => {
  const db = createClient(url, { max: 1, idle_timeout: 1 });
  const rows = (await db.execute(
    sql`SELECT prune_kbjwt_replay_log(${olderThan}::interval) AS deleted`,
  )) as Array<{ deleted: number | string | bigint }>;
  const raw = rows[0]?.deleted ?? 0;
  const deleted = typeof raw === "number" ? raw : Number(raw);
  return { deleted, olderThan };
};

const runPruneReplayLog = async (
  argv: readonly string[],
  io: { out: (s: string) => void; err: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const olderThanFlag = parsed.flags.get("older-than") ?? DEFAULT_OLDER_THAN;
  const interval = parseDuration(olderThanFlag);
  const url = databaseUrl(env);
  const res = await prunePactReplayLog(url, interval);
  io.out(
    `pruned ${res.deleted} kbjwt_replay_log row${res.deleted === 1 ? "" : "s"} older than ${res.olderThan}\n`,
  );
};

export type WhatTarget = "keys" | "audiences" | "all";

const isWhatTarget = (v: string): v is WhatTarget =>
  v === "keys" || v === "audiences" || v === "all";

export type BackfillAction = {
  workspaceId: string;
  workspaceSlug: string;
  hmacCreated: boolean;
  provenanceCreated: boolean;
  audiencesInserted: string[];
};

export type BackfillSummary = {
  scanned: number;
  hmacCreated: number;
  provenanceCreated: number;
  audiencesInserted: number;
  actions: BackfillAction[];
};

const HMAC_BACKFILL_LOCK_TAG = 0x70_61_63_74; // "pact" in hex, namespace for advisory lock

const ensureHmacKey = async (
  db: DbClient,
  workspaceId: string,
  rawMek: Uint8Array,
  dryRun: boolean,
): Promise<boolean> => {
  return withWorkspace(db, workspaceId, async (tx) => {
    await tx.execute(
      sql`SELECT pg_advisory_xact_lock(hashtextextended(${workspaceId} || ':' || ${ADAPTER_DRIVE_KIND}, ${HMAC_BACKFILL_LOCK_TAG}))`,
    );
    try {
      await loadActiveHmacKey(tx, workspaceId, ADAPTER_DRIVE_KIND, rawMek);
      return false;
    } catch {
      if (dryRun) return true;
      await createHmacKey(tx, { workspaceId, kind: ADAPTER_DRIVE_KIND, rawMek });
      return true;
    }
  });
};

const ensureProvenanceKey = async (
  db: DbClient,
  workspaceId: string,
  rawMek: Uint8Array,
  dryRun: boolean,
): Promise<boolean> => {
  return withWorkspace(db, workspaceId, async (tx) => {
    await tx.execute(
      sql`SELECT pg_advisory_xact_lock(hashtextextended(${workspaceId} || ':' || ${PROVENANCE_KIND}, ${HMAC_BACKFILL_LOCK_TAG}))`,
    );
    try {
      await loadActiveSigningKey(tx, workspaceId, PROVENANCE_KIND, rawMek);
      return false;
    } catch {
      if (dryRun) return true;
      await createSigningKey(tx, { workspaceId, kind: PROVENANCE_KIND, rawMek });
      return true;
    }
  });
};

const ensureAudiences = async (
  db: DbClient,
  workspaceId: string,
  dryRun: boolean,
): Promise<string[]> => {
  const inserted: string[] = [];
  for (const aud of DEFAULT_AUDIENCES) {
    const existing = await withWorkspace(db, workspaceId, (tx) =>
      tx
        .select({ id: schema.workspaceAudiences.id })
        .from(schema.workspaceAudiences)
        .where(
          and(
            eq(schema.workspaceAudiences.workspaceId, workspaceId),
            eq(schema.workspaceAudiences.name, aud.name),
            isNull(schema.workspaceAudiences.revokedAt),
          ),
        )
        .limit(1),
    );
    if (existing.length > 0) continue;
    if (!dryRun) {
      const result = await withWorkspace(db, workspaceId, (tx) =>
        tx
          .insert(schema.workspaceAudiences)
          .values({ workspaceId, name: aud.name, description: aud.description })
          .onConflictDoNothing()
          .returning({ id: schema.workspaceAudiences.id }),
      );
      if (result.length === 0) continue;
    }
    inserted.push(aud.name);
  }
  return inserted;
};

export type BackfillOptions = {
  databaseUrl: string;
  rawMek: Uint8Array;
  workspaceId?: string;
  what: WhatTarget;
  dryRun: boolean;
};

export const runBackfill = async (opts: BackfillOptions): Promise<BackfillSummary> => {
  const db = createClient(opts.databaseUrl);
  const workspaceRows = opts.workspaceId
    ? await db
        .select({ id: schema.workspaces.id, slug: schema.workspaces.slug })
        .from(schema.workspaces)
        .where(eq(schema.workspaces.id, opts.workspaceId))
    : await db
        .select({ id: schema.workspaces.id, slug: schema.workspaces.slug })
        .from(schema.workspaces);

  const actions: BackfillAction[] = [];
  let hmacCreated = 0;
  let provenanceCreated = 0;
  let audiencesInserted = 0;

  for (const ws of workspaceRows) {
    const action: BackfillAction = {
      workspaceId: ws.id,
      workspaceSlug: ws.slug,
      hmacCreated: false,
      provenanceCreated: false,
      audiencesInserted: [],
    };

    if (opts.what === "keys" || opts.what === "all") {
      action.hmacCreated = await ensureHmacKey(db, ws.id, opts.rawMek, opts.dryRun);
      if (action.hmacCreated) hmacCreated += 1;
      action.provenanceCreated = await ensureProvenanceKey(db, ws.id, opts.rawMek, opts.dryRun);
      if (action.provenanceCreated) provenanceCreated += 1;
    }

    if (opts.what === "audiences" || opts.what === "all") {
      action.audiencesInserted = await ensureAudiences(db, ws.id, opts.dryRun);
      audiencesInserted += action.audiencesInserted.length;
    }

    actions.push(action);
  }

  return {
    scanned: workspaceRows.length,
    hmacCreated,
    provenanceCreated,
    audiencesInserted,
    actions,
  };
};

export const formatBackfillSummary = (summary: BackfillSummary, dryRun: boolean): string => {
  const lines: string[] = [];
  const prefix = dryRun ? "would " : "";
  lines.push(`scanned ${summary.scanned} workspace${summary.scanned === 1 ? "" : "s"}`);
  for (const a of summary.actions) {
    const parts: string[] = [];
    if (a.hmacCreated) parts.push(`${prefix}create adapter-drive hmac key`);
    if (a.provenanceCreated) parts.push(`${prefix}create provenance signing key`);
    if (a.audiencesInserted.length > 0) {
      parts.push(`${prefix}insert audiences [${a.audiencesInserted.join(", ")}]`);
    }
    if (parts.length === 0) parts.push("nothing to do");
    lines.push(`${a.workspaceSlug} (${a.workspaceId}): ${parts.join("; ")}`);
  }
  lines.push(
    `total: ${prefix}create ${summary.hmacCreated} hmac key${summary.hmacCreated === 1 ? "" : "s"}, ${prefix}create ${summary.provenanceCreated} provenance key${summary.provenanceCreated === 1 ? "" : "s"}, ${prefix}insert ${summary.audiencesInserted} audience row${summary.audiencesInserted === 1 ? "" : "s"}`,
  );
  return `${lines.join("\n")}\n`;
};

const runBackfillCommand = async (
  argv: readonly string[],
  io: { out: (s: string) => void; err: (s: string) => void },
  env: NodeJS.ProcessEnv,
): Promise<void> => {
  const parsed = parseFlags(argv);
  const url = databaseUrl(env);
  const mekB64 = env.MEK;
  if (!mekB64 || mekB64.length === 0) {
    throw new Error("missing MEK");
  }
  const rawMek = fromBase64(mekB64);
  const workspaceId = parsed.flags.get("workspace");
  const whatRaw = parsed.flags.get("what") ?? "all";
  if (!isWhatTarget(whatRaw)) {
    throw new Error("--what must be one of keys, audiences, all");
  }
  const dryRun = parsed.booleans.has("dry-run");
  const summary = await runBackfill({
    databaseUrl: url,
    rawMek,
    ...(workspaceId ? { workspaceId } : {}),
    what: whatRaw,
    dryRun,
  });
  io.out(formatBackfillSummary(summary, dryRun));
};

export type RunResult = { exitCode: number };

export const runAdmin = async (
  argv: readonly string[],
  io: { out: (s: string) => void; err: (s: string) => void } = {
    out: (s) => process.stdout.write(s),
    err: (s) => process.stderr.write(s),
  },
  env: NodeJS.ProcessEnv = process.env,
): Promise<RunResult> => {
  const sub = argv[0];
  const rest = argv.slice(1);
  try {
    switch (sub) {
      case "prune-replay-log":
        await runPruneReplayLog(rest, io, env);
        return { exitCode: 0 };
      case "backfill":
        await runBackfillCommand(rest, io, env);
        return { exitCode: 0 };
      default:
        io.err(
          [
            "usage: pact admin prune-replay-log [--older-than 7d]",
            "       pact admin backfill [--workspace id] [--what keys|audiences|all] [--dry-run]",
            "",
            "env:",
            "  DATABASE_URL  postgres dsn",
            "  MEK           base64 master encryption key (required for backfill)",
            "",
          ].join("\n"),
        );
        return { exitCode: 1 };
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    io.err(`error: ${msg}\n`);
    return { exitCode: 1 };
  }
};
