import { sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres, { type Options } from "postgres";

export type DbClient = ReturnType<typeof createClient>;

export const createClient = (url: string, options?: Partial<Options<Record<string, never>>>) => {
  const defaultMax = process.env.PG_POOL_MAX ? Number.parseInt(process.env.PG_POOL_MAX, 10) : 5;
  const defaultIdle = process.env.PG_IDLE_TIMEOUT
    ? Number.parseInt(process.env.PG_IDLE_TIMEOUT, 10)
    : undefined;
  const quiet = process.env.PACT_QUIET_PG_NOTICES === "1";
  const client = postgres(url, {
    max: defaultMax,
    ...(defaultIdle !== undefined ? { idle_timeout: defaultIdle } : {}),
    ...(quiet ? { onnotice: () => {} } : {}),
    ...options,
  });
  return drizzle(client);
};

const checkedRuntimeRoles = new Set<string>();

export class UnsafeRuntimeDbRoleError extends Error {
  constructor() {
    super("unsafe runtime database role");
    this.name = "UnsafeRuntimeDbRoleError";
  }
}

export const assertSafeRuntimeDbRole = async (
  url: string,
  opts: { production?: boolean; expectedRole?: string } = {},
): Promise<void> => {
  if (!opts.production) return;
  const expectedRole = opts.expectedRole ?? "pact_app";
  const cacheKey = `${url}:${expectedRole}`;
  if (checkedRuntimeRoles.has(cacheKey)) return;

  const client = postgres(url, { max: 1 });
  try {
    const rows = (await client`
      SELECT current_user, rolsuper, rolbypassrls
      FROM pg_roles
      WHERE rolname = current_user
    `) as Array<{ current_user: string; rolsuper: boolean; rolbypassrls: boolean }>;
    const row = rows[0];
    if (!row) throw new Error("runtime database role not found");
    if (row.current_user !== expectedRole || row.rolsuper || row.rolbypassrls) {
      throw new UnsafeRuntimeDbRoleError();
    }
    checkedRuntimeRoles.add(cacheKey);
  } finally {
    await client.end();
  }
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
