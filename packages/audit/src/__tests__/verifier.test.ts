import {
  exportPublicSpki,
  generateEd25519Keypair,
  importPublicSpki,
  jcsBytes,
  sha256,
  signEd25519,
  toBase64,
} from "@getpact/crypto";
import { describe, expect, it } from "vitest";
import { computeGenesisHash } from "../genesis.js";
import { type StoredEvent, verifyChain } from "../verifier.js";

const buildEvent = async (
  base: Omit<StoredEvent, "thisHash" | "signature">,
  signingKey: CryptoKey,
): Promise<StoredEvent> => {
  const canonical = jcsBytes({
    workspaceId: base.workspaceId,
    ts: base.ts,
    actorKind: base.actorKind,
    actorId: base.actorId,
    action: base.action,
    target: base.target,
    decision: base.decision,
    supporting: base.supporting,
    signingKeyId: base.signingKeyId,
    prevHash: base.prevHash,
  });
  const hash = await sha256(canonical);
  const sig = await signEd25519(signingKey, hash);
  return { ...base, thisHash: toBase64(hash), signature: toBase64(sig) };
};

const buildChain = async (
  workspaceId: string,
  genesis: string,
  signingKey: CryptoKey,
  count: number,
): Promise<StoredEvent[]> => {
  const events: StoredEvent[] = [];
  let prev = genesis;
  for (let i = 0; i < count; i++) {
    const event = await buildEvent(
      {
        workspaceId,
        ts: new Date(2026, 0, 1, 0, 0, i).toISOString(),
        actorKind: "system",
        actorId: null,
        action: "test.event",
        target: { i },
        decision: "allow",
        supporting: null,
        signingKeyId: "ws-audit-v1",
        prevHash: prev,
      },
      signingKey,
    );
    events.push(event);
    prev = event.thisHash;
  }
  return events;
};

describe("verifyChain", () => {
  const workspaceId = "00000000-0000-4000-8000-000000000001";
  const createdAt = new Date("2026-01-01T00:00:00Z");

  it("validates a clean 5-event chain", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const genesis = await computeGenesisHash(workspaceId, createdAt);
    const events = await buildChain(workspaceId, genesis, privateKey, 5);
    const spki = await exportPublicSpki(publicKey);
    const reimportedPub = await importPublicSpki(spki);
    const result = await verifyChain(events, { "ws-audit-v1": reimportedPub }, genesis);
    expect(result.ok).toBe(true);
  });

  it("detects a tampered event field", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const genesis = await computeGenesisHash(workspaceId, createdAt);
    const events = await buildChain(workspaceId, genesis, privateKey, 5);
    const tampered = events.map((e, i) => (i === 2 ? { ...e, action: "tampered.action" } : e));
    const result = await verifyChain(tampered, { "ws-audit-v1": publicKey }, genesis);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.brokenAt.index).toBe(2);
      expect(result.brokenAt.reason).toBe("this_hash mismatch");
    }
  });

  it("detects a deleted event", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const genesis = await computeGenesisHash(workspaceId, createdAt);
    const events = await buildChain(workspaceId, genesis, privateKey, 5);
    const withDeletion = [...events.slice(0, 2), ...events.slice(3)];
    const result = await verifyChain(withDeletion, { "ws-audit-v1": publicKey }, genesis);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.brokenAt.index).toBe(2);
      expect(result.brokenAt.reason).toBe("prev_hash mismatch");
    }
  });

  it("detects reordered events", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const genesis = await computeGenesisHash(workspaceId, createdAt);
    const events = await buildChain(workspaceId, genesis, privateKey, 4);
    const e1 = events[1];
    const e2 = events[2];
    if (!e1 || !e2) throw new Error("setup");
    const reordered = [events[0], e2, e1, events[3]] as StoredEvent[];
    const result = await verifyChain(reordered, { "ws-audit-v1": publicKey }, genesis);
    expect(result.ok).toBe(false);
  });

  it("detects a tampered signature", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const genesis = await computeGenesisHash(workspaceId, createdAt);
    const events = await buildChain(workspaceId, genesis, privateKey, 3);
    const tampered = events.map((e, i) =>
      i === 1 ? { ...e, signature: toBase64(new Uint8Array(64)) } : e,
    );
    const result = await verifyChain(tampered, { "ws-audit-v1": publicKey }, genesis);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.brokenAt.index).toBe(1);
      expect(result.brokenAt.reason).toBe("signature invalid");
    }
  });

  it("fails with unknown signing_key_id", async () => {
    const { privateKey } = await generateEd25519Keypair();
    const genesis = await computeGenesisHash(workspaceId, createdAt);
    const events = await buildChain(workspaceId, genesis, privateKey, 2);
    const result = await verifyChain(events, {}, genesis);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.brokenAt.reason).toBe("unknown signing_key_id");
    }
  });

  it("accepts ts as Date instance", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const genesis = await computeGenesisHash(workspaceId, createdAt);
    const events = await buildChain(workspaceId, genesis, privateKey, 3);
    const asDateTs: StoredEvent[] = events.map((e) => ({ ...e, ts: new Date(e.ts as string) }));
    const result = await verifyChain(asDateTs, { "ws-audit-v1": publicKey }, genesis);
    expect(result.ok).toBe(true);
  });

  it("accepts ts as postgres TIMESTAMPTZ text", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const genesis = await computeGenesisHash(workspaceId, createdAt);
    const events = await buildChain(workspaceId, genesis, privateKey, 3);
    const asPgText: StoredEvent[] = events.map((e) => {
      const iso = e.ts as string;
      const pgText = iso.replace("T", " ").replace("Z", "+00");
      return { ...e, ts: pgText };
    });
    const result = await verifyChain(asPgText, { "ws-audit-v1": publicKey }, genesis);
    expect(result.ok).toBe(true);
  });

  it("fails with wrong genesis", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    const genesis = await computeGenesisHash(workspaceId, createdAt);
    const events = await buildChain(workspaceId, genesis, privateKey, 2);
    const wrongGenesis = await computeGenesisHash(workspaceId, new Date("2025-01-01"));
    const result = await verifyChain(events, { "ws-audit-v1": publicKey }, wrongGenesis);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.brokenAt.index).toBe(0);
      expect(result.brokenAt.reason).toBe("prev_hash mismatch");
    }
  });
});
