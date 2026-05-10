-- Replace global unique (workspace_id, kind) with partial unique on active brains.
-- Allows deprecated brains (status != 'active') to coexist with a new active brain of the same kind.

DROP INDEX IF EXISTS "brains_workspace_kind_idx";
CREATE UNIQUE INDEX "brains_workspace_kind_idx"
  ON "brains" USING btree ("workspace_id", "kind")
  WHERE "status" = 'active';
