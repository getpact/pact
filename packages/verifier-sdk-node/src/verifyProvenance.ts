import canonicalize from "canonicalize";
import { exportJWK, type KeyLike } from "jose";
import { type JwksCache, JwksFetchError, sharedJwksCache } from "./jwks.js";

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

export type VerifyProvenanceOptionsKey = {
  workspaceId: string;
  publicKey: CryptoKey;
  maxAgeSeconds?: number;
  now?: () => Date;
};

export type VerifyProvenanceOptionsJwks = {
  workspaceId: string;
  jwksUri: string;
  maxAgeSeconds?: number;
  now?: () => Date;
  jwksCache?: JwksCache;
};

export type VerifyProvenanceOptions = VerifyProvenanceOptionsKey | VerifyProvenanceOptionsJwks;

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

const hasJwksUri = (o: VerifyProvenanceOptions): o is VerifyProvenanceOptionsJwks =>
  typeof (o as VerifyProvenanceOptionsJwks).jwksUri === "string" &&
  (o as VerifyProvenanceOptionsJwks).jwksUri.length > 0;

const resolveKeyFromJwks = async (
  opts: VerifyProvenanceOptionsJwks,
  kid: string,
): Promise<{ ok: true; key: KeyLike | Uint8Array } | { ok: false; reason: string }> => {
  const cache = opts.jwksCache ?? sharedJwksCache;
  try {
    const key = await cache.resolve(opts.jwksUri, kid);
    return { ok: true, key };
  } catch (err) {
    if (err instanceof JwksFetchError) {
      if (err.message.includes("has no key with kid")) {
        return { ok: false, reason: "unknown_kid" };
      }
      return { ok: false, reason: "jwks_fetch_failed" };
    }
    return { ok: false, reason: "jwks_fetch_failed" };
  }
};

const toCryptoKey = async (key: CryptoKey | KeyLike): Promise<CryptoKey> => {
  if (key instanceof CryptoKey) return key;
  const jwk = await exportJWK(key as KeyLike);
  return crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, true, ["verify"]);
};

const verifySignatureBytes = async (
  key: CryptoKey | KeyLike,
  signature: Uint8Array,
  bytes: Uint8Array,
): Promise<boolean> => {
  const cryptoKey = await toCryptoKey(key);
  return crypto.subtle.verify(
    "Ed25519",
    cryptoKey,
    signature as BufferSource,
    bytes as BufferSource,
  );
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

  let key: CryptoKey | KeyLike;
  if (hasJwksUri(options)) {
    const resolved = await resolveKeyFromJwks(options, p.kid);
    if (!resolved.ok) {
      return { ok: false, reason: resolved.reason };
    }
    if (resolved.key instanceof Uint8Array) {
      return { ok: false, reason: "unsupported_key_type" };
    }
    key = resolved.key;
  } else {
    key = options.publicKey;
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
    ok = await verifySignatureBytes(key, signature, bytes);
  } catch {
    return { ok: false, reason: "verify_failed" };
  }
  if (!ok) {
    return { ok: false, reason: "signature_mismatch" };
  }
  return { ok: true };
};
