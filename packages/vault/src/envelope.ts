import {
  type AesEnvelope,
  decryptAesGcm,
  encryptAesGcm,
  exportAesKey,
  fromBase64,
  generateAesKey,
  importAesKey,
  toBase64,
} from "@getpact/crypto";

const IV_BYTES = 12;

const serialize = (env: AesEnvelope): string => {
  const merged = new Uint8Array(env.iv.length + env.ciphertext.length);
  merged.set(env.iv, 0);
  merged.set(env.ciphertext, env.iv.length);
  return toBase64(merged);
};

const parse = (blob: string): AesEnvelope => {
  const merged = fromBase64(blob);
  if (merged.length < IV_BYTES + 1) throw new Error("envelope too short");
  return {
    iv: merged.slice(0, IV_BYTES),
    ciphertext: merged.slice(IV_BYTES),
  };
};

export type WrappedSecret = {
  ciphertext: string;
  dekCiphertext: string;
};

export const wrapSecret = async (mek: CryptoKey, plaintext: Uint8Array): Promise<WrappedSecret> => {
  const dek = await generateAesKey();
  const secretEnv = await encryptAesGcm(dek, plaintext);
  const dekRaw = await exportAesKey(dek);
  const dekEnv = await encryptAesGcm(mek, dekRaw);
  return {
    ciphertext: serialize(secretEnv),
    dekCiphertext: serialize(dekEnv),
  };
};

export const unwrapSecret = async (mek: CryptoKey, wrapped: WrappedSecret): Promise<Uint8Array> => {
  const dekRaw = await decryptAesGcm(mek, parse(wrapped.dekCiphertext));
  const dek = await importAesKey(dekRaw);
  return decryptAesGcm(dek, parse(wrapped.ciphertext));
};
