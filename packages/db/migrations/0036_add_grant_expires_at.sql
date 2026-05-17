ALTER TABLE agent_capability_grants ADD COLUMN IF NOT EXISTS expires_at timestamptz;
CREATE INDEX IF NOT EXISTS agent_capability_grants_expires_at_idx
  ON agent_capability_grants(workspace_id, expires_at)
  WHERE revoked_at IS NULL AND expires_at IS NOT NULL;
