export type DriveAttestationPayload = {
  source_uri: string;
  content_hash: string;
  audience: string[];
  issued_at: number;
};

export type DriveAttestation = {
  payload: string;
  mac: string;
};

export const DRIVE_SOURCE_URI_PREFIX = "gdrive://";
export const DRIVE_ATTESTATION_MAX_SKEW_SECONDS = 300;

const textEncoder = new TextEncoder();

const toBase64 = (bytes: Uint8Array): string => {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i] as number);
  }
  return btoa(binary);
};

const fromBase64 = (value: string): Uint8Array => {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(value, "base64"));
  }
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
};

const sha256Hex = async (value: string): Promise<string> => {
  const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(value));
  const bytes = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const b = bytes[i] as number;
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
};

const hmacSign = async (keyBytes: Uint8Array, message: Uint8Array): Promise<Uint8Array> => {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, message as BufferSource);
  return new Uint8Array(sig);
};

const hmacVerify = async (
  keyBytes: Uint8Array,
  message: Uint8Array,
  tag: Uint8Array,
): Promise<boolean> => {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  return crypto.subtle.verify("HMAC", key, tag as BufferSource, message as BufferSource);
};

export const computeDriveContentHash = (content: string): Promise<string> => sha256Hex(content);

export const sortAudience = (audience: string[]): string[] => [...audience].sort();

export const serializeDriveAttestationPayload = (payload: DriveAttestationPayload): string =>
  JSON.stringify({
    source_uri: payload.source_uri,
    content_hash: payload.content_hash,
    audience: sortAudience(payload.audience),
    issued_at: payload.issued_at,
  });

export type SignDriveAttestationInput = {
  keyBytes: Uint8Array;
  sourceUri: string;
  content: string;
  audience: string[];
  issuedAt?: number;
};

export const signDriveAttestation = async (
  input: SignDriveAttestationInput,
): Promise<DriveAttestation> => {
  const contentHash = await computeDriveContentHash(input.content);
  const issuedAt = input.issuedAt ?? Math.floor(Date.now() / 1000);
  const payload = serializeDriveAttestationPayload({
    source_uri: input.sourceUri,
    content_hash: contentHash,
    audience: input.audience,
    issued_at: issuedAt,
  });
  const mac = await hmacSign(input.keyBytes, textEncoder.encode(payload));
  return { payload, mac: toBase64(mac) };
};

export type DriveAttestationVerifyInput = {
  keyBytes: Uint8Array;
  attestation: DriveAttestation;
  sourceUri: string;
  contentHash: string;
  audience: string[];
  now?: number;
  maxSkewSeconds?: number;
};

export type DriveAttestationVerifyResult =
  | { ok: true; payload: DriveAttestationPayload }
  | { ok: false; reason: string };

const parsePayload = (raw: string): DriveAttestationPayload | null => {
  try {
    const parsed = JSON.parse(raw) as Partial<DriveAttestationPayload>;
    if (typeof parsed.source_uri !== "string") return null;
    if (typeof parsed.content_hash !== "string") return null;
    if (typeof parsed.issued_at !== "number" || !Number.isFinite(parsed.issued_at)) return null;
    if (!Array.isArray(parsed.audience)) return null;
    if (!parsed.audience.every((v) => typeof v === "string")) return null;
    return {
      source_uri: parsed.source_uri,
      content_hash: parsed.content_hash,
      audience: parsed.audience,
      issued_at: parsed.issued_at,
    };
  } catch {
    return null;
  }
};

const audienceEqualsSorted = (a: string[], b: string[]): boolean => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
};

export const verifyDriveAttestation = async (
  input: DriveAttestationVerifyInput,
): Promise<DriveAttestationVerifyResult> => {
  let macBytes: Uint8Array;
  try {
    macBytes = fromBase64(input.attestation.mac);
  } catch {
    return { ok: false, reason: "mac_decode_failed" };
  }
  const macOk = await hmacVerify(
    input.keyBytes,
    textEncoder.encode(input.attestation.payload),
    macBytes,
  );
  if (!macOk) return { ok: false, reason: "mac_mismatch" };

  const payload = parsePayload(input.attestation.payload);
  if (!payload) return { ok: false, reason: "payload_invalid" };

  if (payload.source_uri !== input.sourceUri) {
    return { ok: false, reason: "source_uri_mismatch" };
  }
  if (payload.content_hash !== input.contentHash) {
    return { ok: false, reason: "content_hash_mismatch" };
  }

  const expectedAudience = sortAudience(input.audience);
  const payloadAudience = sortAudience(payload.audience);
  if (!audienceEqualsSorted(expectedAudience, payloadAudience)) {
    return { ok: false, reason: "audience_mismatch" };
  }

  const now = input.now ?? Math.floor(Date.now() / 1000);
  const skew = input.maxSkewSeconds ?? DRIVE_ATTESTATION_MAX_SKEW_SECONDS;
  if (Math.abs(now - payload.issued_at) > skew) {
    return { ok: false, reason: "issued_at_out_of_window" };
  }

  return { ok: true, payload };
};

export const decodeAttestation = (value: unknown): DriveAttestation | null => {
  if (!value || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  if (typeof v.payload !== "string" || typeof v.mac !== "string") return null;
  return { payload: v.payload, mac: v.mac };
};
