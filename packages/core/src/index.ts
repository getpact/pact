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
  return !weakSecretMarkers.some((marker) => lower.includes(marker));
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

const blockedHosts = new Set(["localhost", "0.0.0.0", "127.0.0.1", "::1", "[::1]"]);

export const isPrivateHost = (host: string): boolean => {
  const value = host.toLowerCase();
  if (blockedHosts.has(value) || value.endsWith(".local")) return true;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) return true;
  if (/^169\.254\./.test(value)) return true;
  const match = value.match(/^172\.(\d+)\./);
  if (match?.[1]) {
    const n = Number(match[1]);
    if (n >= 16 && n <= 31) return true;
  }
  if (value.includes(":")) return true;
  return value.startsWith("[fc") || value.startsWith("[fd") || value.startsWith("[fe80");
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
