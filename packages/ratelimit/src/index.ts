import type { Context, MiddlewareHandler, Next } from "hono";

export type RateLimitResult = {
  allowed: boolean;
  remaining: number;
  resetAt: number;
};

export type RateLimiter = {
  hit: (key: string, limit: number, windowSeconds: number) => Promise<RateLimitResult>;
};

export type RateLimitKey = (c: Context) => string;

type Bucket = {
  count: number;
  resetAt: number;
};

const validateLimit = (limit: number, windowSeconds: number): void => {
  if (!Number.isInteger(limit) || limit <= 0) {
    throw new Error("limit must be a positive integer");
  }
  if (!Number.isFinite(windowSeconds) || windowSeconds <= 0) {
    throw new Error("windowSeconds must be positive");
  }
};

const nextBucket = (current: Bucket | undefined, windowSeconds: number): Bucket => {
  const now = Date.now();
  const bucket =
    current && current.resetAt > now ? current : { count: 0, resetAt: now + windowSeconds * 1000 };
  bucket.count += 1;
  return bucket;
};

const toResult = (bucket: Bucket, limit: number): RateLimitResult => ({
  allowed: bucket.count <= limit,
  remaining: Math.max(limit - bucket.count, 0),
  resetAt: bucket.resetAt,
});

export const memoryRateLimiter = (): RateLimiter => {
  const buckets = new Map<string, Bucket>();
  let hits = 0;
  return {
    async hit(key, limit, windowSeconds) {
      validateLimit(limit, windowSeconds);
      hits += 1;
      if (hits % 256 === 0) {
        const now = Date.now();
        for (const [bucketKey, bucket] of buckets) {
          if (bucket.resetAt <= now) buckets.delete(bucketKey);
        }
      }
      const bucket = nextBucket(buckets.get(key), windowSeconds);
      buckets.set(key, bucket);
      return toResult(bucket, limit);
    },
  };
};

export type RateLimitMiddlewareOptions = {
  limiter: RateLimiter;
  limit: number;
  windowSeconds: number;
  keyFn?: RateLimitKey;
};

const defaultKey: RateLimitKey = (c) =>
  c.req.header("cf-connecting-ip") ??
  c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ??
  "anonymous";

const applyResult = async (
  c: Context,
  next: Next,
  limit: number,
  result: RateLimitResult,
): Promise<undefined | Response> => {
  c.header("x-ratelimit-limit", String(limit));
  c.header("x-ratelimit-remaining", String(result.remaining));
  c.header("x-ratelimit-reset", String(Math.ceil(result.resetAt / 1000)));

  if (!result.allowed) {
    const retryAfter = Math.max(Math.ceil((result.resetAt - Date.now()) / 1000), 1);
    c.header("retry-after", String(retryAfter));
    return c.json({ error: "rate_limited" }, 429);
  }

  await next();
  return undefined;
};

export const rateLimit = (opts: RateLimitMiddlewareOptions): MiddlewareHandler => {
  const keyFn = opts.keyFn ?? defaultKey;
  return async (c, next) => {
    const result = await opts.limiter.hit(keyFn(c), opts.limit, opts.windowSeconds);
    return applyResult(c, next, opts.limit, result);
  };
};

export type FixedWindowRateLimitOptions = {
  windowMs: number;
  max: number;
  key?: RateLimitKey;
};

const buildOpts = (
  limiter: RateLimiter,
  opts: FixedWindowRateLimitOptions,
): RateLimitMiddlewareOptions => {
  const base: RateLimitMiddlewareOptions = {
    limiter,
    limit: opts.max,
    windowSeconds: opts.windowMs / 1000,
  };
  if (opts.key) base.keyFn = opts.key;
  return base;
};

export const memoryRateLimit = (opts: FixedWindowRateLimitOptions): MiddlewareHandler =>
  rateLimit(buildOpts(memoryRateLimiter(), opts));

export { databaseRateLimiter, sweepExpiredRateBuckets } from "./db.js";
