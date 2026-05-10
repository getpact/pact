const IV_LENGTH = 12;

export type AesEnvelope = {
  ciphertext: Uint8Array;
  iv: Uint8Array;
};

export const generateAesKey = async (): Promise<CryptoKey> =>
  crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

export const importAesKey = async (raw: Uint8Array): Promise<CryptoKey> =>
  crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);

export const exportAesKey = async (key: CryptoKey): Promise<Uint8Array> => {
  const buf = await crypto.subtle.exportKey("raw", key);
  return new Uint8Array(buf);
};

export const encryptAesGcm = async (
  key: CryptoKey,
  plaintext: Uint8Array,
): Promise<AesEnvelope> => {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    plaintext as BufferSource,
  );
  return { ciphertext: new Uint8Array(ct), iv };
};

export const decryptAesGcm = async (key: CryptoKey, envelope: AesEnvelope): Promise<Uint8Array> => {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: envelope.iv as BufferSource },
    key,
    envelope.ciphertext as BufferSource,
  );
  return new Uint8Array(pt);
};
