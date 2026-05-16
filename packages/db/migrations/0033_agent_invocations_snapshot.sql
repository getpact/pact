-- Preserve agent and user identity on agent_invocations after the parent FK is
-- broken. Without this, hard-deleting an agent or user destroyed the audit
-- link between an executed capability and the principal that ran it.
--
-- Snapshot columns are populated by a BEFORE INSERT trigger as a safety net
-- so every write path keeps the historical id even if it forgets to set the
-- snapshot column explicitly.

ALTER TABLE agent_invocations
  ADD COLUMN IF NOT EXISTS agent_id_snapshot uuid;

ALTER TABLE agent_invocations
  ADD COLUMN IF NOT EXISTS on_behalf_of_user_id_snapshot uuid;

UPDATE agent_invocations
   SET agent_id_snapshot = agent_id
 WHERE agent_id_snapshot IS NULL;

UPDATE agent_invocations
   SET on_behalf_of_user_id_snapshot = on_behalf_of_user_id
 WHERE on_behalf_of_user_id_snapshot IS NULL
   AND on_behalf_of_user_id IS NOT NULL;

ALTER TABLE agent_invocations
  ALTER COLUMN agent_id_snapshot SET NOT NULL;

CREATE OR REPLACE FUNCTION agent_invocations_fill_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.agent_id_snapshot IS NULL THEN
    NEW.agent_id_snapshot := NEW.agent_id;
  END IF;
  IF NEW.on_behalf_of_user_id_snapshot IS NULL THEN
    NEW.on_behalf_of_user_id_snapshot := NEW.on_behalf_of_user_id;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS agent_invocations_fill_snapshot_trg ON agent_invocations;
CREATE TRIGGER agent_invocations_fill_snapshot_trg
  BEFORE INSERT ON agent_invocations
  FOR EACH ROW
  EXECUTE FUNCTION agent_invocations_fill_snapshot();

ALTER TABLE agent_invocations DROP CONSTRAINT IF EXISTS agent_invocations_agent_id_fkey;
ALTER TABLE agent_invocations
  ALTER COLUMN agent_id DROP NOT NULL;
ALTER TABLE agent_invocations
  ADD CONSTRAINT agent_invocations_agent_id_fkey
  FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL;

ALTER TABLE agent_invocations DROP CONSTRAINT IF EXISTS agent_invocations_on_behalf_of_user_id_fkey;
ALTER TABLE agent_invocations
  ADD CONSTRAINT agent_invocations_on_behalf_of_user_id_fkey
  FOREIGN KEY (on_behalf_of_user_id) REFERENCES users(id) ON DELETE SET NULL;

-- agent_capability_grants cascades from agents. Without relaxing this FK the
-- cascade would be blocked by agent_invocations.grant_id, defeating the whole
-- point of the snapshot work.
ALTER TABLE agent_invocations DROP CONSTRAINT IF EXISTS agent_invocations_grant_id_fkey;
ALTER TABLE agent_invocations
  ADD CONSTRAINT agent_invocations_grant_id_fkey
  FOREIGN KEY (grant_id) REFERENCES agent_capability_grants(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS agent_invocations_agent_snapshot_idx
  ON agent_invocations(workspace_id, agent_id_snapshot, issued_at DESC);
