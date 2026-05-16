CREATE TABLE IF NOT EXISTS agent_capability_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  on_behalf_of_user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  on_behalf_of_pattern text,
  tool_name text NOT NULL,
  scope jsonb NOT NULL,
  max_uses_per_day int NOT NULL DEFAULT 1000,
  default_exp_ttl_seconds int NOT NULL DEFAULT 300,
  audience text[] NOT NULL DEFAULT '{}',
  policy_version int NOT NULL DEFAULT 1,
  created_by_user_id uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  CHECK (on_behalf_of_user_id IS NOT NULL OR on_behalf_of_pattern IS NOT NULL)
);

CREATE INDEX agent_capability_grants_agent_tool_idx
  ON agent_capability_grants(workspace_id, agent_id, tool_name)
  WHERE revoked_at IS NULL;

CREATE INDEX agent_capability_grants_scope_gin
  ON agent_capability_grants USING gin (scope jsonb_path_ops);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_capability_grants TO pact_app;

ALTER TABLE agent_capability_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_capability_grants FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON agent_capability_grants
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);
