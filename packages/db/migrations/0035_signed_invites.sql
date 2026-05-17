-- Extend invites for signed invite tokens. Adds a JTI for replay tracking,
-- a list of group ids the invitee joins on accept, ttl in seconds (the
-- existing ttl column stays as the human-friendly label like "7d"), and
-- single-use claim columns that survive a deleted user via a snapshot.

ALTER TABLE invites
  ADD COLUMN IF NOT EXISTS jti uuid;

UPDATE invites SET jti = gen_random_uuid() WHERE jti IS NULL;

ALTER TABLE invites
  ALTER COLUMN jti SET NOT NULL;

ALTER TABLE invites
  ADD COLUMN IF NOT EXISTS group_ids uuid[] NOT NULL DEFAULT '{}';

ALTER TABLE invites
  ADD COLUMN IF NOT EXISTS ttl_seconds integer;

UPDATE invites
   SET ttl_seconds = CASE ttl
     WHEN '1h' THEN 3600
     WHEN '1d' THEN 86400
     WHEN '1w' THEN 604800
     WHEN '1m' THEN 2592000
     ELSE 86400
   END
 WHERE ttl_seconds IS NULL;

ALTER TABLE invites
  ALTER COLUMN ttl_seconds SET NOT NULL;

ALTER TABLE invites
  ADD COLUMN IF NOT EXISTS issued_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE invites
  ADD COLUMN IF NOT EXISTS consumed_at timestamptz;

ALTER TABLE invites
  ADD COLUMN IF NOT EXISTS consumed_user_id uuid REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE invites
  ADD COLUMN IF NOT EXISTS consumed_user_id_snapshot uuid;

ALTER TABLE invites
  DROP CONSTRAINT IF EXISTS invites_jti_unique;
ALTER TABLE invites
  ADD CONSTRAINT invites_jti_unique UNIQUE (workspace_id, jti);

CREATE INDEX IF NOT EXISTS invites_pending_email_idx
  ON invites(workspace_id, email) WHERE consumed_at IS NULL;
