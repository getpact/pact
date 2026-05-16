export { DEFAULT_AUDIENCES, type DefaultAudience } from "./audiences.js";

export type WorkspaceId = string & { readonly _brand: "WorkspaceId" };
export type UserId = string & { readonly _brand: "UserId" };
export type TokenId = string & { readonly _brand: "TokenId" };
export type GroupId = string & { readonly _brand: "GroupId" };
export type RoleId = string & { readonly _brand: "RoleId" };

export type Email = string & { readonly _brand: "Email" };

export const canonicalizeEmail = (raw: string): Email => raw.trim().toLowerCase() as Email;

export type PactTokenMode = "A" | "B";

export const PACT_AUDIENCE_MODES = {
  "pact-admin": "A",
  "pact-audit": "A",
  "pact-mcp": "A",
  "pact-gateway": "B",
} as const satisfies Record<string, PactTokenMode>;

export const tokenModeForAudience = (audience: string): PactTokenMode | null =>
  Object.hasOwn(PACT_AUDIENCE_MODES, audience)
    ? PACT_AUDIENCE_MODES[audience as keyof typeof PACT_AUDIENCE_MODES]
    : null;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const isUuid = (value: unknown): value is string =>
  typeof value === "string" && UUID_RE.test(value);

const MAX_TIMING_SAFE_COMPARE_LENGTH = 4096;

export const timingSafeEqualString = (a: string, b: string): boolean => {
  let diff = a.length ^ b.length;
  if (a.length > MAX_TIMING_SAFE_COMPARE_LENGTH || b.length > MAX_TIMING_SAFE_COMPARE_LENGTH) {
    diff |= 1;
  }
  for (let i = 0; i < MAX_TIMING_SAFE_COMPARE_LENGTH; i++) {
    const left = i < a.length ? a.charCodeAt(i) : 0;
    const right = i < b.length ? b.charCodeAt(i) : 0;
    diff |= left ^ right;
  }
  return diff === 0;
};

const weakSecretMarkers = ["changeme", "replace", "placeholder", "secret", "password", "todo"];

export const isStrongSharedSecret = (value: string | undefined): boolean => {
  const secret = value?.trim();
  if (!secret || secret.length < 32) return false;
  for (let i = 0; i < secret.length; i++) {
    const code = secret.charCodeAt(i);
    if (code <= 32 || code === 127) return false;
  }
  const lower = secret.toLowerCase();
  if (weakSecretMarkers.some((marker) => lower.includes(marker))) return false;
  const unique = new Set(secret).size;
  if (unique < 16) return false;
  return true;
};

export class PactError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, message: string, status: number) {
    super(message);
    this.code = code;
    this.status = status;
    this.name = new.target.name;
  }
}

export class AuthError extends PactError {
  constructor(message: string) {
    super("auth", message, 401);
  }
}

export class AuthzError extends PactError {
  constructor(message: string) {
    super("forbidden", message, 403);
  }
}

export class NotFoundError extends PactError {
  constructor(message: string) {
    super("not_found", message, 404);
  }
}

export class ValidationError extends PactError {
  constructor(message: string) {
    super("invalid_request", message, 400);
  }
}

export class ConflictError extends PactError {
  constructor(message: string) {
    super("conflict", message, 409);
  }
}

export type SecurityHeaderOptions = {
  production?: boolean;
};

const blockedHostnames = new Set(["localhost", "ip6-localhost", "ip6-loopback"]);

const parseUnsignedRadix = (raw: string, radix: number, maxDigits: number): bigint | null => {
  if (raw.length === 0 || raw.length > maxDigits) return null;
  let acc = 0n;
  const base = BigInt(radix);
  for (let i = 0; i < raw.length; i++) {
    const code = raw.charCodeAt(i);
    let digit: number;
    if (code >= 48 && code <= 57) digit = code - 48;
    else if (radix === 16 && code >= 97 && code <= 102) digit = code - 87;
    else return null;
    if (digit >= radix) return null;
    acc = acc * base + BigInt(digit);
  }
  return acc;
};

const parseIpv4Octet = (part: string): bigint | null => {
  if (part.length === 0) return null;
  if (part === "0") return 0n;
  if (part.length >= 2 && part[0] === "0" && (part[1] === "x" || part[1] === "X")) {
    return parseUnsignedRadix(part.slice(2), 16, 8);
  }
  if (part[0] === "0") {
    return parseUnsignedRadix(part.slice(1), 8, 11);
  }
  return parseUnsignedRadix(part, 10, 10);
};

const ipv4PartsToInt = (parts: string[]): bigint | null => {
  if (parts.length === 0 || parts.length > 4) return null;
  const values: bigint[] = [];
  for (const part of parts) {
    const value = parseIpv4Octet(part);
    if (value === null) return null;
    values.push(value);
  }
  const last = values[values.length - 1];
  if (last === undefined) return null;
  const leading = values.slice(0, -1);
  let combined = 0n;
  for (const v of leading) {
    if (v > 0xffn) return null;
    combined = (combined << 8n) | v;
  }
  const remainingBits = BigInt(32 - leading.length * 8);
  const cap = 1n << remainingBits;
  if (last >= cap) return null;
  combined = (combined << remainingBits) | last;
  if (combined > 0xffffffffn) return null;
  return combined;
};

const ipv4NumericLike = /^[0-9a-fA-FxX.]+$/;

const parseIpv4Any = (host: string): bigint | null => {
  if (!ipv4NumericLike.test(host)) return null;
  const parts = host.split(".");
  return ipv4PartsToInt(parts);
};

const ipv4IsPrivateInt = (n: bigint): boolean => {
  if (n < 0n || n > 0xffffffffn) return true;
  const a = Number((n >> 24n) & 0xffn);
  const b = Number((n >> 16n) & 0xffn);
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0 && Number((n >> 8n) & 0xffn) === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
};

const stripIpv6Brackets = (host: string): string =>
  host.length >= 2 && host[0] === "[" && host[host.length - 1] === "]" ? host.slice(1, -1) : host;

const parseIpv6Groups = (raw: string): bigint[] | null => {
  if (raw.length === 0) return null;
  const doubleColonCount = (raw.match(/::/g) ?? []).length;
  if (doubleColonCount > 1) return null;
  let head: string;
  let tail: string;
  if (doubleColonCount === 1) {
    const idx = raw.indexOf("::");
    head = raw.slice(0, idx);
    tail = raw.slice(idx + 2);
  } else {
    head = raw;
    tail = "";
  }
  const splitGroups = (segment: string): string[] | null => {
    if (segment.length === 0) return [];
    const groups = segment.split(":");
    for (const g of groups) {
      if (g.length === 0 || g.length > 4) return null;
      if (!/^[0-9a-f]+$/.test(g)) return null;
    }
    return groups;
  };
  const headGroups = splitGroups(head);
  const tailGroups = splitGroups(tail);
  if (headGroups === null || tailGroups === null) return null;
  const total = headGroups.length + tailGroups.length;
  if (doubleColonCount === 1) {
    if (total > 7) return null;
  } else if (total !== 8) {
    return null;
  }
  const fillCount = 8 - total;
  const all = [
    ...headGroups,
    ...Array.from({ length: doubleColonCount === 1 ? fillCount : 0 }, () => "0"),
    ...tailGroups,
  ];
  if (all.length !== 8) return null;
  const result: bigint[] = [];
  for (const g of all) {
    const v = parseUnsignedRadix(g, 16, 4);
    if (v === null) return null;
    result.push(v);
  }
  return result;
};

const ipv6IsPrivate = (host: string): boolean => {
  const raw = host.toLowerCase();
  const zoneIdx = raw.indexOf("%");
  const cleaned = zoneIdx >= 0 ? raw.slice(0, zoneIdx) : raw;
  const embeddedV4 = cleaned.lastIndexOf(":");
  let normalized = cleaned;
  if (embeddedV4 >= 0 && cleaned.slice(embeddedV4 + 1).includes(".")) {
    const v4Part = cleaned.slice(embeddedV4 + 1);
    const v4Int = parseIpv4Any(v4Part);
    if (v4Int === null) return true;
    const high = Number((v4Int >> 16n) & 0xffffn).toString(16);
    const low = Number(v4Int & 0xffffn).toString(16);
    normalized = `${cleaned.slice(0, embeddedV4 + 1)}${high}:${low}`;
    if (ipv4IsPrivateInt(v4Int)) return true;
  }
  const groups = parseIpv6Groups(normalized);
  if (groups === null) return true;
  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups as [
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
  ];
  if (
    g0 === 0n &&
    g1 === 0n &&
    g2 === 0n &&
    g3 === 0n &&
    g4 === 0n &&
    g5 === 0n &&
    g6 === 0n &&
    g7 === 1n
  )
    return true;
  if (
    g0 === 0n &&
    g1 === 0n &&
    g2 === 0n &&
    g3 === 0n &&
    g4 === 0n &&
    g5 === 0n &&
    g6 === 0n &&
    g7 === 0n
  )
    return true;
  if (g0 === 0n && g1 === 0n && g2 === 0n && g3 === 0n && g4 === 0n && g5 === 0xffffn) {
    const v4 = (g6 << 16n) | g7;
    return ipv4IsPrivateInt(v4);
  }
  if ((g0 & 0xfe00n) === 0xfc00n) return true;
  if ((g0 & 0xffc0n) === 0xfe80n) return true;
  if (g0 === 0x2002n) {
    const v4 = (g1 << 16n) | g2;
    return ipv4IsPrivateInt(v4);
  }
  return false;
};

export const isPrivateHost = (host: string): boolean => {
  if (host.length === 0) return true;
  const value = host.toLowerCase();
  if (blockedHostnames.has(value)) return true;
  if (value.endsWith(".local") || value.endsWith(".internal") || value.endsWith(".localhost"))
    return true;
  if (value[0] === "[" || value.includes(":")) {
    return ipv6IsPrivate(stripIpv6Brackets(value));
  }
  if (ipv4NumericLike.test(value)) {
    const asInt = parseIpv4Any(value);
    if (asInt === null) return true;
    return ipv4IsPrivateInt(asInt);
  }
  return false;
};

export const assertSafeUpstreamUrl = (raw: string): URL => {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ValidationError("invalid upstream url");
  }
  if (url.protocol !== "https:") throw new ValidationError("upstream must use https");
  if (url.username || url.password) throw new ValidationError("upstream credentials forbidden");
  if (isPrivateHost(url.hostname)) throw new ValidationError("upstream host not allowed");
  return url;
};

const allowlistPatterns = (raw: string | undefined): string[] =>
  raw
    ?.split(",")
    .map((v) => v.trim().toLowerCase())
    .filter((v) => v.length > 0) ?? [];

const hostMatchesPattern = (host: string, pattern: string): boolean => {
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(2);
    return host.endsWith(`.${suffix}`);
  }
  return host === pattern;
};

export const assertAllowedUpstreamHost = (
  url: URL,
  rawAllowlist: string | undefined,
  opts: { required?: boolean } = {},
): void => {
  const patterns = allowlistPatterns(rawAllowlist);
  if (patterns.length === 0) {
    if (opts.required) throw new ValidationError("upstream host allowlist required");
    return;
  }
  const host = url.hostname.toLowerCase();
  if (!patterns.some((pattern) => hostMatchesPattern(host, pattern))) {
    throw new ValidationError("upstream host not allowed by allowlist");
  }
};

export const securityHeaders = (opts: SecurityHeaderOptions = {}): Record<string, string> => ({
  "content-security-policy": "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  "cross-origin-resource-policy": "same-origin",
  "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  ...(opts.production
    ? { "strict-transport-security": "max-age=31536000; includeSubDomains; preload" }
    : {}),
});
