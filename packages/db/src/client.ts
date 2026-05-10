import { sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres, { type Options } from "postgres";

export type DbClient = ReturnType<typeof createClient>;

export const createClient = (url: string, options?: Partial<Options<Record<string, never>>>) => {
  const defaultMax = process.env.PG_POOL_MAX ? Number.parseInt(process.env.PG_POOL_MAX, 10) : 5;
  const defaultIdle = process.env.PG_IDLE_TIMEOUT
    ? Number.parseInt(process.env.PG_IDLE_TIMEOUT, 10)
    : undefined;
  const client = postgres(url, {
    max: defaultMax,
    ...(defaultIdle !== undefined ? { idle_timeout: defaultIdle } : {}),
    ...options,
  });
  return drizzle(client);
};

export type Tx = Parameters<Parameters<DbClient["transaction"]>[0]>[0];

export const withWorkspace = async <T>(
  db: DbClient,
  workspaceId: string,
  fn: (tx: Tx) => Promise<T>,
): Promise<T> =>
  db.transaction(async (tx) => {
    await tx.execute(sql`SELECT set_config('app.current_workspace_id', ${workspaceId}, true)`);
    return fn(tx);
  });
