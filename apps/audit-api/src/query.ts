import type { Tx } from "@getpact/db";
import { auditEvents } from "@getpact/db/schema";
import { and, asc, desc, eq, gte, lte, sql } from "drizzle-orm";

export type QueryOrder = "asc" | "desc";

export type QueryInput = {
  workspaceId: string;
  action?: string;
  since?: Date;
  until?: Date;
  limit: number;
  order?: QueryOrder;
  cursor?: { ts: Date; thisHash: string };
};

export type QueryRow = {
  id: string;
  ts: Date;
  actorKind: string;
  actorId: string | null;
  action: string;
  target: unknown;
  decision: string;
  supporting: unknown;
  signingKeyId: string;
  prevHash: string;
  thisHash: string;
  signature: string;
};

export type QueryOutput = {
  events: QueryRow[];
  nextCursor: string | null;
};

export const parseCursor = (raw: string | undefined): QueryInput["cursor"] => {
  if (!raw) return undefined;
  const idx = raw.indexOf(":");
  if (idx <= 0) return undefined;
  const ts = new Date(raw.slice(0, idx));
  const thisHash = raw.slice(idx + 1);
  if (Number.isNaN(ts.valueOf()) || !thisHash) return undefined;
  return { ts, thisHash };
};

export const formatCursor = (row: QueryRow): string => `${row.ts.toISOString()}:${row.thisHash}`;

export const queryEvents = async (tx: Tx, input: QueryInput): Promise<QueryOutput> => {
  const conditions = [eq(auditEvents.workspaceId, input.workspaceId)];
  if (input.action) conditions.push(eq(auditEvents.action, input.action));
  if (input.since) conditions.push(gte(auditEvents.ts, input.since));
  if (input.until) conditions.push(lte(auditEvents.ts, input.until));
  const order = input.order ?? "desc";
  if (input.cursor) {
    const cmp = order === "asc" ? sql`>` : sql`<`;
    conditions.push(
      sql`(${auditEvents.ts}, ${auditEvents.thisHash}) ${cmp} (${input.cursor.ts.toISOString()}, ${input.cursor.thisHash})`,
    );
  }

  const orderClauses =
    order === "asc"
      ? [asc(auditEvents.ts), asc(auditEvents.thisHash)]
      : [desc(auditEvents.ts), desc(auditEvents.thisHash)];

  const rows = await tx
    .select()
    .from(auditEvents)
    .where(and(...conditions))
    .orderBy(...orderClauses)
    .limit(input.limit + 1);

  const hasMore = rows.length > input.limit;
  const trimmed = hasMore ? rows.slice(0, input.limit) : rows;
  const last = trimmed[trimmed.length - 1];

  return {
    events: trimmed.map((r) => ({
      id: r.id,
      ts: r.ts,
      actorKind: r.actorKind,
      actorId: r.actorId,
      action: r.action,
      target: r.target,
      decision: r.decision,
      supporting: r.supporting,
      signingKeyId: r.signingKeyId,
      prevHash: r.prevHash,
      thisHash: r.thisHash,
      signature: r.signature,
    })),
    nextCursor: hasMore && last ? formatCursor(last) : null,
  };
};
