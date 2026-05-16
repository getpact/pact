import canonicalize from "canonicalize";

export type ProvenanceSigned = {
  source_uri: string;
  chunk_index: number;
  chunk_id: string | null;
  page_id: string | null;
  issued_at: string;
  kid: string;
  signature: string;
};

export type SearchHit = {
  provenance: ProvenanceSigned;
};

export type VerifyProvenanceOptions = {
  workspaceId: string;
  publicKey: CryptoKey;
  maxAgeSeconds?: number;
  now?: () => Date;
};

export type VerifyProvenanceResult = { ok: true } | { ok: false; reason: string };

const DEFAULT_MAX_AGE_SECONDS = 3600;

const fromBase64Url = (input: string): Uint8Array => {
  const pad = (4 - (input.length % 4)) % 4;
  const padded = input.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

const isProvenanceShape = (value: unknown): value is ProvenanceSigned => {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.source_uri !== "string") return false;
  if (typeof v.chunk_index !== "number") return false;
  if (v.chunk_id !== null && typeof v.chunk_id !== "string") return false;
  if (v.page_id !== null && typeof v.page_id !== "string") return false;
  if (typeof v.issued_at !== "string") return false;
  if (typeof v.kid !== "string") return false;
  if (typeof v.signature !== "string") return false;
  return true;
};

export const verifyProvenance = async (
  hit: SearchHit,
  options: VerifyProvenanceOptions,
): Promise<VerifyProvenanceResult> => {
  const p = hit?.provenance;
  if (!isProvenanceShape(p)) {
    return { ok: false, reason: "missing_signature_fields" };
  }

  const issuedAtMs = Date.parse(p.issued_at);
  if (!Number.isFinite(issuedAtMs)) {
    return { ok: false, reason: "invalid_issued_at" };
  }
  const maxAge = options.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;
  const now = (options.now ?? (() => new Date()))().getTime();
  if (Math.abs(now - issuedAtMs) > maxAge * 1000) {
    return { ok: false, reason: "stale" };
  }

  const payload = {
    workspace_id: options.workspaceId,
    page_id: p.page_id,
    chunk_id: p.chunk_id,
    source_uri: p.source_uri,
    chunk_index: p.chunk_index,
    issued_at: p.issued_at,
  };
  const canonical = canonicalize(payload);
  if (canonical === undefined) {
    return { ok: false, reason: "canonicalize_failed" };
  }
  const bytes = new TextEncoder().encode(canonical);

  let signature: Uint8Array;
  try {
    signature = fromBase64Url(p.signature);
  } catch {
    return { ok: false, reason: "invalid_signature_encoding" };
  }

  let ok: boolean;
  try {
    ok = await crypto.subtle.verify(
      "Ed25519",
      options.publicKey,
      signature as BufferSource,
      bytes as BufferSource,
    );
  } catch {
    return { ok: false, reason: "verify_failed" };
  }
  if (!ok) {
    return { ok: false, reason: "signature_mismatch" };
  }
  return { ok: true };
};
