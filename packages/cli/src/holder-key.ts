import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

export type HolderKey = {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: { kty: "OKP"; crv: "Ed25519"; x: string };
};

type StoredKey = {
  version: 1;
  privatePkcs8Base64: string;
  publicJwk: { kty: "OKP"; crv: "Ed25519"; x: string };
};

const dir = (): string => join(homedir(), ".pact");
const path = (): string => join(dir(), "holder.key");

const toBase64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");
const fromBase64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64"));

const exportPublicJwk = async (
  key: CryptoKey,
): Promise<{ kty: "OKP"; crv: "Ed25519"; x: string }> => {
  const jwk = (await crypto.subtle.exportKey("jwk", key)) as Record<string, unknown>;
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error("unexpected jwk shape for ed25519 public key");
  }
  return { kty: "OKP", crv: "Ed25519", x: jwk.x };
};

const generate = async (): Promise<HolderKey> => {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const publicJwk = await exportPublicJwk(pair.publicKey);
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk };
};

const persist = async (key: HolderKey): Promise<void> => {
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", key.privateKey));
  const record: StoredKey = {
    version: 1,
    privatePkcs8Base64: toBase64(pkcs8),
    publicJwk: key.publicJwk,
  };
  await mkdir(dir(), { recursive: true, mode: 0o700 });
  await chmod(dir(), 0o700);
  await writeFile(path(), `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
  await chmod(path(), 0o600);
};

const importStored = async (record: StoredKey): Promise<HolderKey> => {
  const bytes = fromBase64(record.privatePkcs8Base64);
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    bytes as BufferSource,
    { name: "Ed25519" },
    true,
    ["sign"],
  );
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    record.publicJwk,
    { name: "Ed25519" },
    true,
    ["verify"],
  );
  return { privateKey, publicKey, publicJwk: record.publicJwk };
};

export const loadHolderKey = async (): Promise<HolderKey | null> => {
  let raw: string;
  try {
    raw = await readFile(path(), "utf8");
  } catch {
    return null;
  }
  const parsed = JSON.parse(raw) as StoredKey;
  if (parsed.version !== 1) {
    throw new Error(`unsupported holder key version ${parsed.version}`);
  }
  return importStored(parsed);
};

export const loadOrCreateHolderKey = async (): Promise<HolderKey> => {
  const existing = await loadHolderKey();
  if (existing) return existing;
  const fresh = await generate();
  await persist(fresh);
  return fresh;
};

export const holderKeyPath = (): string => path();
