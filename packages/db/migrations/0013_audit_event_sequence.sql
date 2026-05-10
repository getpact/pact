ALTER TABLE "audit_events" ADD COLUMN "audit_seq" bigint;--> statement-breakpoint
WITH RECURSIVE ordered AS (
  SELECT e.id, e.workspace_id, e.this_hash, 1::bigint AS audit_seq
  FROM audit_events e
  WHERE NOT EXISTS (
    SELECT 1
    FROM audit_events p
    WHERE p.workspace_id = e.workspace_id
      AND p.this_hash = e.prev_hash
  )
  UNION ALL
  SELECT e.id, e.workspace_id, e.this_hash, ordered.audit_seq + 1
  FROM audit_events e
  JOIN ordered
    ON ordered.workspace_id = e.workspace_id
   AND ordered.this_hash = e.prev_hash
)
UPDATE audit_events e
SET audit_seq = ordered.audit_seq
FROM ordered
WHERE e.id = ordered.id;--> statement-breakpoint
WITH max_existing AS (
  SELECT workspace_id, COALESCE(MAX(audit_seq), 0) AS max_audit_seq
  FROM audit_events
  GROUP BY workspace_id
),
ranked AS (
  SELECT
    e.id,
    (m.max_audit_seq + row_number() OVER (PARTITION BY e.workspace_id ORDER BY e.ts, e.this_hash))::bigint AS audit_seq
  FROM audit_events e
  JOIN max_existing m ON m.workspace_id = e.workspace_id
  WHERE e.audit_seq IS NULL
)
UPDATE audit_events e
SET audit_seq = ranked.audit_seq
FROM ranked
WHERE e.id = ranked.id;--> statement-breakpoint
ALTER TABLE "audit_events" ALTER COLUMN "audit_seq" SET NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "audit_events_workspace_seq_idx" ON "audit_events" USING btree ("workspace_id","audit_seq");
