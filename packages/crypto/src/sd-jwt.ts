import { type Ed25519PublicJwk, signEd25519, validateCnfJwk, verifyEd25519 } from "./ed25519.js";
import { fromBase64Url, sha256, toBase64Url } from "./hash.js";
import { jcsCanonicalize } from "./jcs.js";

const KB_JWT_TYP = "kb+jwt";
const SD_JWT_TYP = "sd+jwt";
const SD_ALG = "sha-256";

export type SdJwtDisclosureInput = {
  name: string;
  value: unknown;
  salt?: string;
};

export type IssuerClaims = Record<string, unknown>;

export type CnfJwk = Ed25519PublicJwk;

export type IssueSdJwtOptions = {
  issuerPrivateKey: CryptoKey;
  issuerKid: string;
  issuerClaims: IssuerClaims;
  disclosures: SdJwtDisclosureInput[];
  cnfJkt?: CnfJwk;
};

export type SignKbJwtOptions = {
  holderPrivateKey: CryptoKey;
  sdJwt: string;
  audience: string;
  nonce: string;
};

export type IssuerJwks = {
  keys: Array<Ed25519PublicJwk & { kid: string }>;
};

export type VerifySdJwtOptions = {
  compactSdJwt: string;
  issuerJwks: IssuerJwks;
  expectedAudience?: string;
  expectedNonce?: string;
  requireKbBinding?: boolean;
};

export type VerifySdJwtResult = {
  claims: Record<string, unknown>;
  disclosed: Record<string, unknown>;
  kbClaims?: Record<string, unknown>;
};

export class SdJwtError extends Error {
  public readonly code: string;
  public constructor(code: string, message: string) {
    super(`${code}: ${message}`);
    this.name = "SdJwtError";
    this.code = code;
  }
}

const enc = new TextEncoder();
const dec = new TextDecoder();

const encodeJsonSegment = (value: unknown): string =>
  toBase64Url(enc.encode(JSON.stringify(value)));

const decodeJsonSegment = <T>(seg: string): T => JSON.parse(dec.decode(fromBase64Url(seg))) as T;

const randomSalt = (): string => toBase64Url(crypto.getRandomValues(new Uint8Array(16)));

// JCS keeps the disclosure hash stable across encoders so the issuer hash and
// the verifier rehash agree without depending on whitespace or key order.
const disclosureToken = (d: SdJwtDisclosureInput): string => {
  const salt = d.salt ?? randomSalt();
  const arr: [string, string, unknown] = [salt, d.name, d.value];
  const canonical = jcsCanonicalize(arr);
  return toBase64Url(enc.encode(canonical));
};

const hashDisclosure = async (token: string): Promise<string> => {
  return toBase64Url(await sha256(enc.encode(token)));
};

const signCompactJws = async (
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  key: CryptoKey,
): Promise<string> => {
  const head = encodeJsonSegment(header);
  const body = encodeJsonSegment(payload);
  const signingInput = `${head}.${body}`;
  const sig = await signEd25519(key, enc.encode(signingInput));
  return `${signingInput}.${toBase64Url(sig)}`;
};

const splitJws = (
  jws: string,
): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: Uint8Array;
  signature: Uint8Array;
} => {
  const parts = jws.split(".");
  if (parts.length !== 3) throw new SdJwtError("malformed_jws", "expected three jws segments");
  const [h, p, s] = parts as [string, string, string];
  return {
    header: decodeJsonSegment(h),
    payload: decodeJsonSegment(p),
    signingInput: enc.encode(`${h}.${p}`),
    signature: fromBase64Url(s),
  };
};

const findKey = (jwks: IssuerJwks, kid: string | undefined): Ed25519PublicJwk & { kid: string } => {
  if (!kid) throw new SdJwtError("missing_kid", "issuer jwt header has no kid");
  const found = jwks.keys.find((k) => k.kid === kid);
  if (!found) throw new SdJwtError("unknown_kid", `no jwk for kid ${kid}`);
  return found;
};

const importEd25519Verify = async (jwk: Ed25519PublicJwk): Promise<CryptoKey> =>
  crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, true, ["verify"]);

// RFC 7800 + RFC 9901: JWK thumbprint per RFC 7638 over the canonical OKP
// member set (crv, kty, x) is what the holder proves possession of.
export const jwkThumbprint = async (jwk: Ed25519PublicJwk): Promise<string> => {
  const canonical = jcsCanonicalize({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return toBase64Url(await sha256(enc.encode(canonical)));
};

export const issueSdJwt = async (opts: IssueSdJwtOptions): Promise<string> => {
  const tokens: string[] = [];
  const hashes: string[] = [];
  for (const d of opts.disclosures) {
    const tok = disclosureToken(d);
    tokens.push(tok);
    hashes.push(await hashDisclosure(tok));
  }

  const payload: Record<string, unknown> = {
    ...opts.issuerClaims,
    _sd: hashes,
    _sd_alg: SD_ALG,
  };
  if (opts.cnfJkt) {
    payload.cnf = { jwk: opts.cnfJkt };
  }

  const header = { alg: "EdDSA", typ: SD_JWT_TYP, kid: opts.issuerKid };
  const jws = await signCompactJws(header, payload, opts.issuerPrivateKey);
  return `${[jws, ...tokens].join("~")}~`;
};

export const signKbJwt = async (opts: SignKbJwtOptions): Promise<string> => {
  if (!opts.sdJwt.endsWith("~")) {
    throw new SdJwtError("malformed_sd_jwt", "sd-jwt must end with trailing tilde before kb-jwt");
  }
  const sdHashInput = opts.sdJwt;
  const sdHash = toBase64Url(await sha256(enc.encode(sdHashInput)));
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now,
    aud: opts.audience,
    nonce: opts.nonce,
    sd_hash: sdHash,
  };
  const header = { alg: "EdDSA", typ: KB_JWT_TYP };
  const kb = await signCompactJws(header, payload, opts.holderPrivateKey);
  return `${opts.sdJwt}${kb}`;
};

const parseCompact = (
  compact: string,
): { issuerJws: string; disclosures: string[]; kbJwt?: string } => {
  const parts = compact.split("~");
  if (parts.length < 2)
    throw new SdJwtError("malformed_compact", "compact form needs issuer jwt and trailing tilde");
  const issuerJws = parts[0] as string;
  const last = parts[parts.length - 1] as string;
  let kbJwt: string | undefined;
  let endIdx = parts.length - 1;
  if (last === "") {
    endIdx = parts.length - 1;
  } else {
    kbJwt = last;
    endIdx = parts.length - 1;
  }
  const disclosures = parts.slice(1, endIdx).filter((p) => p.length > 0);
  return kbJwt ? { issuerJws, disclosures, kbJwt } : { issuerJws, disclosures };
};

const applyDisclosures = (
  claims: Record<string, unknown>,
  tokens: string[],
): { disclosed: Record<string, unknown>; expectedHashes: string[] } => {
  const sd = claims._sd;
  if (!Array.isArray(sd)) {
    throw new SdJwtError("missing_sd", "issuer jwt has no _sd array");
  }
  const expectedHashes = sd.map((h) => String(h));
  const disclosed: Record<string, unknown> = {};
  for (const tok of tokens) {
    const parsed = JSON.parse(dec.decode(fromBase64Url(tok))) as [string, string, unknown];
    if (!Array.isArray(parsed) || parsed.length !== 3) {
      throw new SdJwtError("bad_disclosure", "disclosure must be [salt, name, value]");
    }
    const [, name, value] = parsed;
    disclosed[name] = value;
  }
  return { disclosed, expectedHashes };
};

export const verifySdJwt = async (opts: VerifySdJwtOptions): Promise<VerifySdJwtResult> => {
  const { issuerJws, disclosures, kbJwt } = parseCompact(opts.compactSdJwt);
  const parsedIssuer = splitJws(issuerJws);
  const kid = parsedIssuer.header.kid as string | undefined;
  const issuerJwk = findKey(opts.issuerJwks, kid);
  const issuerKey = await importEd25519Verify(issuerJwk);
  const ok = await verifyEd25519(issuerKey, parsedIssuer.signingInput, parsedIssuer.signature);
  if (!ok) throw new SdJwtError("issuer_sig_invalid", "issuer signature did not verify");

  const claims = parsedIssuer.payload;
  const { disclosed, expectedHashes } = applyDisclosures(claims, disclosures);

  const seen = new Set<string>();
  for (const tok of disclosures) {
    const h = await hashDisclosure(tok);
    if (!expectedHashes.includes(h)) {
      throw new SdJwtError("disclosure_hash_mismatch", "disclosure not present in issuer _sd");
    }
    if (seen.has(h)) {
      throw new SdJwtError("disclosure_duplicate", "duplicate disclosure presented");
    }
    seen.add(h);
  }

  let kbClaims: Record<string, unknown> | undefined;
  if (kbJwt) {
    const cnf = claims.cnf as { jwk?: unknown } | undefined;
    if (!cnf?.jwk) {
      throw new SdJwtError("kb_without_cnf", "kb-jwt presented but issuer jwt has no cnf.jwk");
    }
    const validated = validateCnfJwk(cnf.jwk);
    if ("error" in validated) {
      throw new SdJwtError("kb_cnf_invalid", validated.error);
    }
    const parsedKb = splitJws(kbJwt);
    if (parsedKb.header.typ !== KB_JWT_TYP) {
      throw new SdJwtError("kb_wrong_typ", `kb-jwt typ must be ${KB_JWT_TYP}`);
    }
    const holderKey = await importEd25519Verify(validated);
    const kbOk = await verifyEd25519(holderKey, parsedKb.signingInput, parsedKb.signature);
    if (!kbOk) {
      throw new SdJwtError("kb_sig_invalid", "kb-jwt signature did not verify under cnf.jwk");
    }
    const kbPayload = parsedKb.payload;
    const sdInput = opts.compactSdJwt.slice(0, opts.compactSdJwt.length - kbJwt.length);
    const expectedSdHash = toBase64Url(await sha256(enc.encode(sdInput)));
    if (kbPayload.sd_hash !== expectedSdHash) {
      throw new SdJwtError("kb_sd_hash_mismatch", "kb-jwt sd_hash does not bind this sd-jwt");
    }
    if (opts.expectedAudience !== undefined && kbPayload.aud !== opts.expectedAudience) {
      throw new SdJwtError("kb_wrong_audience", "kb-jwt audience does not match expected");
    }
    if (opts.expectedNonce !== undefined && kbPayload.nonce !== opts.expectedNonce) {
      throw new SdJwtError("kb_wrong_nonce", "kb-jwt nonce does not match expected");
    }
    kbClaims = kbPayload;
  } else if (opts.requireKbBinding) {
    throw new SdJwtError("kb_required", "kb-jwt required but not present");
  }

  const issuerView: Record<string, unknown> = { ...claims };
  delete issuerView._sd;
  delete issuerView._sd_alg;

  return kbClaims !== undefined
    ? { claims: issuerView, disclosed, kbClaims }
    : { claims: issuerView, disclosed };
};
