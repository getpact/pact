import { createClient, type DbClient } from "@getpact/db";
import type { RateLimiter, RateLimitResult } from "@getpact/ratelimit";
import { sql } from "drizzle-orm";

const dbLimiters = new Map<string, RateLimiter>();

export const sweepExpiredRateBuckets = async (db: DbClient): Promise<number> => {
  const rows = (await db.execute(
    sql`DELETE FROM rate_limit_buckets WHERE reset_at < NOW() - INTERVAL '1 hour' RETURNING key`,
  )) as Array<{ key: string }>;
  return rows.length;
};

export const databaseRateLimiter = (databaseUrl: string): RateLimiter => {
  const cached = dbLimiters.get(databaseUrl);
  if (cached) return cached;

  const db = createClient(databaseUrl);
  const limiter: RateLimiter = {
    async hit(key, limit, windowSeconds): Promise<RateLimitResult> {
      const rows = (await db.execute(
        sql`INSERT INTO rate_limit_buckets (key, count, reset_at)
            VALUES (${key}, 1, NOW() + ${windowSeconds} * INTERVAL '1 second')
            ON CONFLICT (key) DO UPDATE
            SET count = CASE
                  WHEN rate_limit_buckets.reset_at <= NOW() THEN 1
                  ELSE rate_limit_buckets.count + 1
                END,
                reset_at = CASE
                  WHEN rate_limit_buckets.reset_at <= NOW()
                    THEN NOW() + ${windowSeconds} * INTERVAL '1 second'
                  ELSE rate_limit_buckets.reset_at
                END,
                updated_at = NOW()
            RETURNING count, reset_at`,
      )) as Array<{ count: number | string; reset_at: Date | string }>;
      const row = rows[0];
      if (!row) throw new Error("rate limit write returned no row");
      const count = Number(row.count);
      const resetAt =
        row.reset_at instanceof Date ? row.reset_at.getTime() : new Date(row.reset_at).getTime();
      return {
        allowed: count <= limit,
        remaining: Math.max(limit - count, 0),
        resetAt,
      };
    },
  };

  dbLimiters.set(databaseUrl, limiter);
  return limiter;
};
