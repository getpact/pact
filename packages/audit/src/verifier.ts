import { fromBase64, jcsBytes, sha256, toBase64, verifyEd25519 } from "@getpact/crypto";

export type StoredEvent = {
  workspaceId: string;
  ts: string | Date;
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

export type AuditJwks = Record<string, CryptoKey>;

export type VerifyResult =
  | { ok: true }
  | { ok: false; brokenAt: { index: number; reason: string } };

const normalizeTs = (ts: string | Date): string => {
  if (ts instanceof Date) return ts.toISOString();
  return new Date(ts).toISOString();
};

const buildCanonicalBody = (event: StoredEvent) => ({
  workspaceId: event.workspaceId,
  ts: normalizeTs(event.ts),
  actorKind: event.actorKind,
  actorId: event.actorId,
  action: event.action,
  target: event.target,
  decision: event.decision,
  supporting: event.supporting,
  signingKeyId: event.signingKeyId,
  prevHash: event.prevHash,
});

export const verifyChain = async (
  events: StoredEvent[],
  jwks: AuditJwks,
  genesisHash: string,
): Promise<VerifyResult> => {
  let expectedPrev = genesisHash;
  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    if (!event) {
      return { ok: false, brokenAt: { index: i, reason: "missing event" } };
    }

    if (event.prevHash !== expectedPrev) {
      return { ok: false, brokenAt: { index: i, reason: "prev_hash mismatch" } };
    }

    const canonical = jcsBytes(buildCanonicalBody(event));
    const recomputed = toBase64(await sha256(canonical));
    if (recomputed !== event.thisHash) {
      return { ok: false, brokenAt: { index: i, reason: "this_hash mismatch" } };
    }

    const publicKey = jwks[event.signingKeyId];
    if (!publicKey) {
      return { ok: false, brokenAt: { index: i, reason: "unknown signing_key_id" } };
    }

    const ok = await verifyEd25519(
      publicKey,
      fromBase64(event.thisHash),
      fromBase64(event.signature),
    );
    if (!ok) {
      return { ok: false, brokenAt: { index: i, reason: "signature invalid" } };
    }

    expectedPrev = event.thisHash;
  }
  return { ok: true };
};
