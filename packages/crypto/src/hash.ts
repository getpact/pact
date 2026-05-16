export const sha256 = async (data: Uint8Array): Promise<Uint8Array> => {
  const hash = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return new Uint8Array(hash);
};

export const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

export const fromHex = (hex: string): Uint8Array => {
  if (hex.length % 2 !== 0) throw new Error("invalid hex length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

export const toBase64 = (bytes: Uint8Array): string => {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
};

export const fromBase64 = (b64: string): Uint8Array => {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
};

export const toBase64Url = (bytes: Uint8Array): string =>
  toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

export const fromBase64Url = (b64u: string): Uint8Array => {
  const pad = b64u.length % 4 === 0 ? "" : "=".repeat(4 - (b64u.length % 4));
  return fromBase64(b64u.replace(/-/g, "+").replace(/_/g, "/") + pad);
};
