import type { Tx } from "@getpact/db";
import { auditEvents } from "@getpact/db/schema";
import { and, asc, desc, eq, gt, gte, lt, lte } from "drizzle-orm";

export type QueryOrder = "asc" | "desc";

export type QueryInput = {
  workspaceId: string;
  action?: string;
  since?: Date;
  until?: Date;
  limit: number;
  order?: QueryOrder;
  cursor?: { auditSeq: number };
};

export type QueryRow = {
  id: string;
  workspaceId: string;
  auditSeq: number;
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
  if (!/^[1-9]\d*$/.test(raw)) return undefined;
  const auditSeq = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(auditSeq)) return undefined;
  return { auditSeq };
};

export const formatCursor = (row: QueryRow): string => String(row.auditSeq);

export const queryEvents = async (tx: Tx, input: QueryInput): Promise<QueryOutput> => {
  const conditions = [eq(auditEvents.workspaceId, input.workspaceId)];
  if (input.action) conditions.push(eq(auditEvents.action, input.action));
  if (input.since) conditions.push(gte(auditEvents.ts, input.since));
  if (input.until) conditions.push(lte(auditEvents.ts, input.until));
  const order = input.order ?? "desc";
  if (input.cursor) {
    conditions.push(
      order === "asc"
        ? gt(auditEvents.auditSeq, input.cursor.auditSeq)
        : lt(auditEvents.auditSeq, input.cursor.auditSeq),
    );
  }

  const orderClauses = order === "asc" ? [asc(auditEvents.auditSeq)] : [desc(auditEvents.auditSeq)];

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
      workspaceId: r.workspaceId,
      auditSeq: r.auditSeq,
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
