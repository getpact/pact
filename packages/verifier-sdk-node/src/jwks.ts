import { importJWK, type JSONWebKeySet, type KeyLike } from "jose";

export type JwksFetcher = (url: string) => Promise<JSONWebKeySet>;

export type JwksCacheOptions = {
  ttlMs?: number;
  fetcher?: JwksFetcher;
};

type CacheEntry = {
  expiresAt: number;
  keys: Map<string, KeyLike | Uint8Array>;
};

const DEFAULT_TTL_MS = 5 * 60 * 1000;

export class JwksFetchError extends Error {
  override readonly cause: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "JwksFetchError";
    this.cause = cause;
  }
}

const defaultFetcher: JwksFetcher = async (url) => {
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) {
    throw new JwksFetchError(`jwks endpoint returned ${res.status}`);
  }
  const body = (await res.json()) as JSONWebKeySet;
  if (!body || !Array.isArray(body.keys)) {
    throw new JwksFetchError("jwks response missing keys array");
  }
  return body;
};

export class JwksCache {
  private readonly ttlMs: number;
  private readonly fetcher: JwksFetcher;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(options: JwksCacheOptions = {}) {
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.fetcher = options.fetcher ?? defaultFetcher;
  }

  async resolve(url: string, kid: string): Promise<KeyLike | Uint8Array> {
    const now = Date.now();
    const existing = this.cache.get(url);
    if (existing && existing.expiresAt > now) {
      const key = existing.keys.get(kid);
      if (key) return key;
    }

    let jwks: JSONWebKeySet;
    try {
      jwks = await this.fetcher(url);
    } catch (err) {
      if (err instanceof JwksFetchError) throw err;
      throw new JwksFetchError("failed to fetch jwks", err);
    }

    const keys = new Map<string, KeyLike | Uint8Array>();
    for (const jwk of jwks.keys) {
      if (!jwk || typeof jwk.kid !== "string") continue;
      try {
        const imported = await importJWK(jwk, jwk.alg ?? "EdDSA");
        keys.set(jwk.kid, imported);
      } catch {
        // skip keys we cannot import; matching by kid will surface the failure
      }
    }
    this.cache.set(url, { expiresAt: now + this.ttlMs, keys });

    const key = keys.get(kid);
    if (!key) {
      throw new JwksFetchError(`jwks at ${url} has no key with kid ${kid}`);
    }
    return key;
  }

  invalidate(url?: string): void {
    if (url === undefined) {
      this.cache.clear();
      return;
    }
    this.cache.delete(url);
  }
}

export const sharedJwksCache = new JwksCache();
