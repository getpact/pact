import { drizzle } from "drizzle-orm/postgres-js";
import postgres, { type Options } from "postgres";

export type DbClient = ReturnType<typeof createClient>;

export const createClient = (url: string, options?: Partial<Options<Record<string, never>>>) => {
  const sql = postgres(url, { max: 10, ...options });
  return drizzle(sql);
};
