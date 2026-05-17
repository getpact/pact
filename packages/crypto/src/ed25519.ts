export type Ed25519Keypair = {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
};

export const generateEd25519Keypair = async (): Promise<Ed25519Keypair> => {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicKey: pair.publicKey };
};

export const signEd25519 = async (privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> => {
  const sig = await crypto.subtle.sign("Ed25519", privateKey, data as BufferSource);
  return new Uint8Array(sig);
};

export const verifyEd25519 = async (
  publicKey: CryptoKey,
  data: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> =>
  crypto.subtle.verify("Ed25519", publicKey, signature as BufferSource, data as BufferSource);

export const exportPrivatePkcs8 = async (key: CryptoKey): Promise<Uint8Array> => {
  const buf = await crypto.subtle.exportKey("pkcs8", key);
  return new Uint8Array(buf);
};

export const exportPublicSpki = async (key: CryptoKey): Promise<Uint8Array> => {
  const buf = await crypto.subtle.exportKey("spki", key);
  return new Uint8Array(buf);
};

export const importPrivatePkcs8 = async (bytes: Uint8Array): Promise<CryptoKey> =>
  crypto.subtle.importKey("pkcs8", bytes as BufferSource, { name: "Ed25519" }, true, ["sign"]);

export const importPublicSpki = async (bytes: Uint8Array): Promise<CryptoKey> =>
  crypto.subtle.importKey("spki", bytes as BufferSource, { name: "Ed25519" }, true, ["verify"]);

export type Ed25519PublicJwk = {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid?: string;
  alg?: string;
  use?: string;
};

export const importPublicJwkEd25519 = async (jwk: Ed25519PublicJwk): Promise<CryptoKey> =>
  crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, true, ["verify"]);

export type ValidatedCnfJwk = { kty: "OKP"; crv: "Ed25519"; x: string };

export type ValidateCnfJwkResult = ValidatedCnfJwk | { error: string };

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const fromBase64UrlBytes = (s: string): Uint8Array => {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

export const validateCnfJwk = (jwk: unknown): ValidateCnfJwkResult => {
  if (!isRecord(jwk)) {
    return { error: "cnf_jwk must be an object" };
  }
  if (jwk.kty !== "OKP") return { error: "cnf_jwk kty must be OKP" };
  if (jwk.crv !== "Ed25519") return { error: "cnf_jwk crv must be Ed25519" };
  if (typeof jwk.x !== "string" || jwk.x.length === 0) {
    return { error: "cnf_jwk x must be a non-empty string" };
  }
  let raw: Uint8Array;
  try {
    raw = fromBase64UrlBytes(jwk.x);
  } catch {
    return { error: "cnf_jwk x must be valid base64url" };
  }
  if (raw.length !== 32) {
    return { error: "cnf_jwk x must decode to 32 bytes" };
  }
  return { kty: "OKP", crv: "Ed25519", x: jwk.x };
};
