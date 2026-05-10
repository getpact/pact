import { jcsBytes, sha256, signEd25519, toBase64 } from "@getpact/crypto";
import type { Tx } from "@getpact/db";
import { sql } from "drizzle-orm";
import { computeGenesisHash } from "./genesis.js";

export type AuditEventInput = {
  actorKind: "user" | "system" | "agent" | "admin";
  actorId?: string;
  action: string;
  target: unknown;
  decision: "allow" | "deny";
  supporting?: unknown;
};

export type WriteEventOptions = {
  workspaceId: string;
  workspaceCreatedAt: Date;
  signingKeyId: string;
  signingKey: CryptoKey;
  event: AuditEventInput;
  ts?: Date;
};

export type WriteResult = {
  thisHash: string;
  signature: string;
};

export const writeEvent = async (tx: Tx, opts: WriteEventOptions): Promise<WriteResult> => {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`audit:${opts.workspaceId}`}))`);

  const lockedRows = (await tx.execute(
    sql`SELECT last_hash FROM audit_chain_state WHERE workspace_id = ${opts.workspaceId} FOR UPDATE`,
  )) as unknown as Array<{ last_hash: string }>;

  const prevHash =
    lockedRows[0]?.last_hash ??
    (await computeGenesisHash(opts.workspaceId, opts.workspaceCreatedAt));

  const ts = opts.ts ?? new Date();
  const eventBody = {
    workspaceId: opts.workspaceId,
    ts: ts.toISOString(),
    actorKind: opts.event.actorKind,
    actorId: opts.event.actorId ?? null,
    action: opts.event.action,
    target: opts.event.target,
    decision: opts.event.decision,
    supporting: opts.event.supporting ?? null,
    signingKeyId: opts.signingKeyId,
    prevHash,
  };

  const canonicalBytes = jcsBytes(eventBody);
  const thisHashBytes = await sha256(canonicalBytes);
  const thisHash = toBase64(thisHashBytes);
  const signatureBytes = await signEd25519(opts.signingKey, thisHashBytes);
  const signature = toBase64(signatureBytes);

  const inserted = (await tx.execute(
    sql`INSERT INTO audit_events (
      workspace_id, ts, actor_kind, actor_id, action, target,
      decision, supporting, signing_key_id, prev_hash, this_hash, signature
    ) VALUES (
      ${opts.workspaceId}, ${ts.toISOString()}, ${opts.event.actorKind}, ${opts.event.actorId ?? null},
      ${opts.event.action}, ${JSON.stringify(opts.event.target)},
      ${opts.event.decision}, ${opts.event.supporting === undefined ? null : JSON.stringify(opts.event.supporting)},
      ${opts.signingKeyId}, ${prevHash}, ${thisHash}, ${signature}
    ) RETURNING id`,
  )) as unknown as Array<{ id: string }>;

  const newEventId = inserted[0]?.id;
  if (!newEventId) throw new Error("audit insert returned no id");

  await tx.execute(
    sql`INSERT INTO audit_chain_state (workspace_id, last_hash, last_event_id)
        VALUES (${opts.workspaceId}, ${thisHash}, ${newEventId})
        ON CONFLICT (workspace_id) DO UPDATE
        SET last_hash = EXCLUDED.last_hash,
            last_event_id = EXCLUDED.last_event_id,
            updated_at = NOW()`,
  );

  return { thisHash, signature };
};
