import { validateCnfJwk } from "@getpact/crypto";
import { compactVerify, decodeProtectedHeader, importJWK, type KeyLike } from "jose";
import { type JwksCache, JwksFetchError, sharedJwksCache } from "./jwks.js";

const KB_JWT_TYP = "kb+jwt";
const DEFAULT_KB_IAT_SKEW_SECONDS = 300;
const DEFAULT_KB_IAT_MAX_AGE_SECONDS = 300;

export type VerifyOpts = {
  jwksUri: string;
  audience: string;
  toolName?: string;
  resource?: Record<string, unknown>;
  replayCache?: ReplayCache;
  kbIatSkewSeconds?: number;
  /**
   * Maximum age (in seconds) of the KB-JWT iat. A replayed KB-JWT older than
   * (now - this) is rejected even if no replayCache is supplied. Defaults to
   * 300s. Pair with a replayCache for stronger guarantees within the window.
   */
  kbIatMaxAgeSeconds?: number;
  jwksCache?: JwksCache;
  now?: () => number;
};

export type VerifyResult = {
  ok: true;
  jti: string;
  workspaceId: string;
  scopeClaim: Record<string, unknown>;
  audience: string;
  expiresAt: Date;
  agentId?: string;
};

export type DenyReason =
  | "invalid_format"
  | "signature_invalid"
  | "jwks_fetch_failed"
  | "aud_mismatch"
  | "expired"
  | "kb_iat_invalid"
  | "kb_signature_invalid"
  | "kb_binding_invalid"
  | "kb_missing"
  | "tool_mismatch"
  | "resource_required"
  | "scope_mismatch"
  | "kb_replay_detected"
  | "unknown";

export type VerifyDenied = {
  ok: false;
  reason: DenyReason;
  detail?: string;
};

export type ReplayCache = {
  has(key: string): Promise<boolean>;
  add(key: string): Promise<void>;
};

type ParsedCompact = {
  issuerJws: string;
  disclosures: string[];
  kbJwt?: string;
  sdHashInput: string;
};

const enc = new TextEncoder();
const dec = new TextDecoder();

const fromBase64Url = (s: string): Uint8Array => {
  const pad = s.length % 4;
  const padded = pad === 0 ? s : s + "=".repeat(4 - pad);
  const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

const toBase64Url = (bytes: Uint8Array): string => {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] as number);
  return btoa(bin).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
};

const sha256 = async (bytes: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));

const deny = (reason: DenyReason, detail?: string): VerifyDenied =>
  detail === undefined ? { ok: false, reason } : { ok: false, reason, detail };

const parseCompact = (compact: string): ParsedCompact | null => {
  if (typeof compact !== "string" || compact.length === 0) return null;
  const parts = compact.split("~");
  if (parts.length < 2) return null;
  const issuerJws = parts[0];
  if (!issuerJws || issuerJws.split(".").length !== 3) return null;
  const last = parts[parts.length - 1];
  let kbJwt: string | undefined;
  let endIdx: number;
  if (last === "") {
    endIdx = parts.length - 1;
  } else {
    if (!last || last.split(".").length !== 3) return null;
    kbJwt = last;
    endIdx = parts.length - 1;
  }
  const disclosures = parts.slice(1, endIdx).filter((p) => p.length > 0);
  const sdHashInput = kbJwt ? compact.slice(0, compact.length - kbJwt.length) : compact;
  return kbJwt
    ? { issuerJws, disclosures, kbJwt, sdHashInput }
    : { issuerJws, disclosures, sdHashInput };
};

const decodeJsonSegment = <T>(seg: string): T | null => {
  try {
    return JSON.parse(dec.decode(fromBase64Url(seg))) as T;
  } catch {
    return null;
  }
};

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const matchPattern = (scopeValue: unknown, requested: unknown): boolean => {
  if (typeof scopeValue === "string" && typeof requested === "string") {
    if (scopeValue === requested) return true;
    if (scopeValue.endsWith("*")) {
      const prefix = scopeValue.slice(0, -1);
      return requested.startsWith(prefix);
    }
    if (scopeValue === "*") return true;
    return false;
  }
  if (Array.isArray(scopeValue)) {
    return scopeValue.some((v) => matchPattern(v, requested));
  }
  if (isPlainObject(scopeValue) && isPlainObject(requested)) {
    return matchScope(scopeValue, requested);
  }
  return scopeValue === requested;
};

const matchScope = (scope: Record<string, unknown>, resource: Record<string, unknown>): boolean => {
  for (const [k, v] of Object.entries(scope)) {
    if (k === "tool_name") continue;
    if (!(k in resource)) return false;
    if (!matchPattern(v, resource[k])) return false;
  }
  return true;
};

const extractScopeClaim = (
  issuerPayload: Record<string, unknown>,
  disclosed: Record<string, unknown>,
): Record<string, unknown> => {
  const direct = disclosed.scope;
  if (isPlainObject(direct)) return direct;
  const policy = disclosed.policy;
  if (isPlainObject(policy) && isPlainObject(policy.scope)) return policy.scope;
  const claim = issuerPayload.scope_claim;
  if (isPlainObject(claim)) return claim;
  return {};
};

const extractAgentId = (
  issuerPayload: Record<string, unknown>,
  disclosed: Record<string, unknown>,
): string | undefined => {
  const direct = disclosed.agent_id;
  if (typeof direct === "string") return direct;
  const payload = disclosed.payload;
  if (isPlainObject(payload) && typeof payload.agent_id === "string") return payload.agent_id;
  const sub = issuerPayload.sub;
  if (typeof sub === "string" && sub.startsWith("agent_")) return sub.slice("agent_".length);
  return undefined;
};

const collectDisclosed = (disclosures: string[]): Record<string, unknown> => {
  const out: Record<string, unknown> = {};
  for (const tok of disclosures) {
    let arr: unknown;
    try {
      arr = JSON.parse(dec.decode(fromBase64Url(tok)));
    } catch {
      continue;
    }
    if (!Array.isArray(arr) || arr.length !== 3) continue;
    const name = arr[1];
    if (typeof name !== "string") continue;
    out[name] = arr[2];
  }
  return out;
};

export async function verifyPactToken(
  sdJwt: string,
  opts: VerifyOpts,
): Promise<VerifyResult | VerifyDenied> {
  const parsed = parseCompact(sdJwt);
  if (!parsed) return deny("invalid_format", "could not split sd-jwt compact form");

  let header: { kid?: string; alg?: string };
  try {
    header = decodeProtectedHeader(parsed.issuerJws) as { kid?: string; alg?: string };
  } catch {
    return deny("invalid_format", "issuer jwt header could not be decoded");
  }
  const kid = header.kid;
  if (typeof kid !== "string" || kid.length === 0) {
    return deny("invalid_format", "issuer jwt header missing kid");
  }

  const cache = opts.jwksCache ?? sharedJwksCache;
  let issuerKey: KeyLike | Uint8Array;
  try {
    issuerKey = await cache.resolve(opts.jwksUri, kid);
  } catch (err) {
    const detail =
      err instanceof JwksFetchError
        ? err.message
        : err instanceof Error
          ? err.message
          : String(err);
    return deny("jwks_fetch_failed", detail);
  }

  let issuerPayload: Record<string, unknown>;
  try {
    const verified = await compactVerify(parsed.issuerJws, issuerKey);
    const decoded = decodeJsonSegment<Record<string, unknown>>(
      parsed.issuerJws.split(".")[1] ?? "",
    );
    if (!decoded || !verified) return deny("invalid_format", "issuer payload could not be decoded");
    issuerPayload = decoded;
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return deny("signature_invalid", detail);
  }

  const now = (opts.now ?? Date.now)() / 1000;
  const exp = issuerPayload.exp;
  if (typeof exp !== "number" || !Number.isFinite(exp)) {
    return deny("invalid_format", "issuer payload missing exp");
  }
  if (now > exp) return deny("expired");

  const tokenAud = issuerPayload.aud;
  if (typeof tokenAud !== "string" || tokenAud !== opts.audience) {
    return deny("aud_mismatch", `expected ${opts.audience}, got ${String(tokenAud)}`);
  }

  const jti = issuerPayload.jti;
  if (typeof jti !== "string" || jti.length === 0) {
    return deny("invalid_format", "issuer payload missing jti");
  }
  const workspaceId = issuerPayload.org;
  if (typeof workspaceId !== "string" || workspaceId.length === 0) {
    return deny("invalid_format", "issuer payload missing org");
  }

  const disclosed = collectDisclosed(parsed.disclosures);

  if (!parsed.kbJwt) {
    return deny("kb_missing", "kb-jwt required but not present");
  }

  let kbPayload: Record<string, unknown>;
  let kbHeader: { typ?: string; alg?: string };
  try {
    kbHeader = decodeProtectedHeader(parsed.kbJwt) as { typ?: string; alg?: string };
  } catch {
    return deny("kb_binding_invalid", "kb-jwt header could not be decoded");
  }
  if (kbHeader.typ !== KB_JWT_TYP) {
    return deny("kb_binding_invalid", `kb-jwt typ must be ${KB_JWT_TYP}`);
  }

  const cnf = issuerPayload.cnf;
  if (!isPlainObject(cnf) || !isPlainObject(cnf.jwk)) {
    return deny("kb_binding_invalid", "issuer payload missing cnf.jwk");
  }
  const validatedCnf = validateCnfJwk(cnf.jwk);
  if ("error" in validatedCnf) {
    return deny("kb_binding_invalid", validatedCnf.error);
  }
  let holderKey: KeyLike | Uint8Array;
  try {
    holderKey = await importJWK(validatedCnf, kbHeader.alg ?? "EdDSA");
  } catch (err) {
    return deny("kb_binding_invalid", err instanceof Error ? err.message : String(err));
  }

  try {
    const verified = await compactVerify(parsed.kbJwt, holderKey);
    const decoded = decodeJsonSegment<Record<string, unknown>>(parsed.kbJwt.split(".")[1] ?? "");
    if (!decoded || !verified)
      return deny("kb_binding_invalid", "kb-jwt payload could not be decoded");
    kbPayload = decoded;
  } catch (err) {
    return deny("kb_signature_invalid", err instanceof Error ? err.message : String(err));
  }

  const expectedSdHash = toBase64Url(await sha256(enc.encode(parsed.sdHashInput)));
  if (kbPayload.sd_hash !== expectedSdHash) {
    return deny("kb_binding_invalid", "kb-jwt sd_hash does not bind this sd-jwt");
  }

  const kbIat = kbPayload.iat;
  const skew = opts.kbIatSkewSeconds ?? DEFAULT_KB_IAT_SKEW_SECONDS;
  const maxAge = opts.kbIatMaxAgeSeconds ?? DEFAULT_KB_IAT_MAX_AGE_SECONDS;
  if (
    typeof kbIat !== "number" ||
    !Number.isFinite(kbIat) ||
    !Number.isInteger(kbIat) ||
    kbIat <= 0 ||
    kbIat > now + skew ||
    kbIat < now - maxAge
  ) {
    return deny("kb_iat_invalid");
  }

  if (opts.replayCache) {
    const replayKey = `${jti}:${kbIat}:${expectedSdHash}`;
    if (await opts.replayCache.has(replayKey)) {
      return deny("kb_replay_detected");
    }
    await opts.replayCache.add(replayKey);
  }

  const scopeClaim = extractScopeClaim(issuerPayload, disclosed);

  if (opts.toolName !== undefined) {
    const issuerToolName = issuerPayload.tool_name;
    const scopeToolName = scopeClaim.tool_name;
    const observed =
      typeof issuerToolName === "string"
        ? issuerToolName
        : typeof scopeToolName === "string"
          ? scopeToolName
          : undefined;
    if (observed !== opts.toolName) {
      return deny("tool_mismatch", `expected ${opts.toolName}, got ${String(observed)}`);
    }
  }

  if (opts.resource !== undefined) {
    if (!isPlainObject(opts.resource)) {
      return deny("resource_required", "resource option must be an object");
    }
    if (!matchScope(scopeClaim, opts.resource)) {
      return deny("scope_mismatch");
    }
  } else {
    const hasResourceConstraint = Object.keys(scopeClaim).some((k) => k !== "tool_name");
    if (hasResourceConstraint) {
      return deny("resource_required", "token scope requires resource match");
    }
  }

  const expiresAt = new Date(exp * 1000);
  const agentId = extractAgentId(issuerPayload, disclosed);
  const result: VerifyResult = {
    ok: true,
    jti,
    workspaceId,
    scopeClaim,
    audience: tokenAud,
    expiresAt,
    ...(agentId !== undefined ? { agentId } : {}),
  };
  return result;
}
