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
