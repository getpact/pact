import {
  exportPublicSpki,
  fromBase64,
  generateEd25519Keypair,
  importPublicSpki,
  jcsBytes,
  sha256,
  toBase64,
  verifyEd25519,
} from "@getpact/crypto";
import { createClient, type DbClient, withWorkspace } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { computeGenesisHash, writeEvent } from "../index.js";

const url = process.env.RLS_TEST_DB;
const run = url ? describe : describe.skip;

run("audit writer", () => {
  let db: DbClient;
  let workspaceId: string;
  let createdAt: Date;
  let signingKey: CryptoKey;
  let publicKey: CryptoKey;

  beforeAll(async () => {
    db = createClient(url as string);
    const [ws] = await db
      .insert(workspaces)
      .values({ slug: `audit-${Date.now()}`, name: "Audit" })
      .returning();
    if (!ws) throw new Error("workspace insert failed");
    workspaceId = ws.id;
    createdAt = ws.createdAt;
    const pair = await generateEd25519Keypair();
    signingKey = pair.privateKey;
    const spki = await exportPublicSpki(pair.publicKey);
    publicKey = await importPublicSpki(spki);
  });

  afterAll(async () => {
    await db.delete(workspaces).where(eq(workspaces.id, workspaceId));
  });

  it("writes a single event with valid signature and chains from genesis", async () => {
    const result = await withWorkspace(db, workspaceId, (tx) =>
      writeEvent(tx, {
        workspaceId,
        workspaceCreatedAt: createdAt,
        signingKeyId: "ws-audit-v1",
        signingKey,
        event: {
          actorKind: "user",
          actorId: "alice@example.com",
          action: "test.event",
          target: { kind: "doc", id: "abc" },
          decision: "allow",
        },
      }),
    );
    expect(result.thisHash.length).toBeGreaterThan(0);
    expect(result.signature.length).toBeGreaterThan(0);

    const ok = await verifyEd25519(
      publicKey,
      fromBase64(result.thisHash),
      fromBase64(result.signature),
    );
    expect(ok).toBe(true);

    const rows = (await withWorkspace(db, workspaceId, (tx) =>
      tx.execute(sql`SELECT prev_hash FROM audit_events WHERE workspace_id = ${workspaceId}`),
    )) as Array<{ prev_hash: string }>;
    const genesis = await computeGenesisHash(workspaceId, createdAt);
    expect(rows[0]?.prev_hash).toBe(genesis);
  });

  it("chains 100 events with continuous prev_hash linkage", async () => {
    const hashes: string[] = [];
    for (let i = 0; i < 100; i++) {
      const r = await withWorkspace(db, workspaceId, (tx) =>
        writeEvent(tx, {
          workspaceId,
          workspaceCreatedAt: createdAt,
          signingKeyId: "ws-audit-v1",
          signingKey,
          event: {
            actorKind: "system",
            action: "chain.test",
            target: { i },
            decision: "allow",
          },
        }),
      );
      hashes.push(r.thisHash);
    }

    const rows = (await withWorkspace(db, workspaceId, (tx) =>
      tx.execute(
        sql`SELECT prev_hash, this_hash, signature, signing_key_id FROM audit_events WHERE workspace_id = ${workspaceId} AND action = 'chain.test' ORDER BY ts ASC, this_hash ASC`,
      ),
    )) as Array<{
      prev_hash: string;
      this_hash: string;
      signature: string;
      signing_key_id: string;
    }>;

    expect(rows.length).toBe(100);

    let prevExpected = (await withWorkspace(db, workspaceId, (tx) =>
      tx.execute(
        sql`SELECT this_hash FROM audit_events WHERE workspace_id = ${workspaceId} AND action = 'test.event' ORDER BY ts DESC LIMIT 1`,
      ),
    )) as Array<{ this_hash: string }>;
    let cursor = prevExpected[0]?.this_hash;
    if (!cursor) throw new Error("no prior event found");
    for (const row of rows) {
      expect(row.prev_hash).toBe(cursor);
      const ok = await verifyEd25519(
        publicKey,
        fromBase64(row.this_hash),
        fromBase64(row.signature),
      );
      expect(ok).toBe(true);
      cursor = row.this_hash;
    }
  });

  it("recomputes this_hash from canonical event body", async () => {
    const r = await withWorkspace(db, workspaceId, (tx) =>
      writeEvent(tx, {
        workspaceId,
        workspaceCreatedAt: createdAt,
        signingKeyId: "ws-audit-v1",
        signingKey,
        event: {
          actorKind: "user",
          actorId: "verify@example.com",
          action: "recompute.test",
          target: { id: "x" },
          decision: "deny",
        },
      }),
    );

    const rows = (await withWorkspace(db, workspaceId, (tx) =>
      tx.execute(
        sql`SELECT ts, actor_kind, actor_id, action, target, decision, supporting, signing_key_id, prev_hash, this_hash, signature FROM audit_events WHERE this_hash = ${r.thisHash}`,
      ),
    )) as Array<{
      ts: Date;
      actor_kind: string;
      actor_id: string | null;
      action: string;
      target: unknown;
      decision: string;
      supporting: unknown;
      signing_key_id: string;
      prev_hash: string;
      this_hash: string;
      signature: string;
    }>;

    const row = rows[0];
    if (!row) throw new Error("event not found");

    const eventBody = {
      workspaceId,
      ts: new Date(row.ts).toISOString(),
      actorKind: row.actor_kind,
      actorId: row.actor_id ?? null,
      action: row.action,
      target: row.target,
      decision: row.decision,
      supporting: row.supporting ?? null,
      signingKeyId: row.signing_key_id,
      prevHash: row.prev_hash,
    };

    const recomputed = await sha256(jcsBytes(eventBody));
    expect(toBase64(recomputed)).toBe(row.this_hash);

    const ok = await verifyEd25519(publicKey, fromBase64(row.this_hash), fromBase64(row.signature));
    expect(ok).toBe(true);
  });
});
