DO $$
DECLARE
  duplicate_count integer;
BEGIN
  SELECT count(*)
  INTO duplicate_count
  FROM (
    SELECT workspace_id, kind
    FROM brains
    GROUP BY workspace_id, kind
    HAVING count(*) > 1
  ) duplicate_brains;

  IF duplicate_count > 0 THEN
    RAISE EXCEPTION 'cannot create brains_workspace_kind_idx: found % duplicate workspace/kind groups', duplicate_count
      USING ERRCODE = '23505';
  END IF;
END $$;--> statement-breakpoint
CREATE UNIQUE INDEX "brains_workspace_kind_idx" ON "brains" USING btree ("workspace_id","kind");
