CREATE TABLE IF NOT EXISTS delegation_chains (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  parent_jti uuid NOT NULL,
  child_jti uuid NOT NULL,
  parent_agent_id uuid NOT NULL REFERENCES agents(id),
  child_agent_id uuid NOT NULL REFERENCES agents(id),
  scope_reduction jsonb NOT NULL,
  depth int NOT NULL,
  max_depth int NOT NULL DEFAULT 3,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (depth <= max_depth),
  CHECK (depth > 0)
);

CREATE UNIQUE INDEX delegation_chains_child_jti_idx
  ON delegation_chains(workspace_id, child_jti);

CREATE INDEX delegation_chains_parent_jti_idx
  ON delegation_chains(workspace_id, parent_jti);

GRANT SELECT, INSERT, UPDATE, DELETE ON delegation_chains TO pact_app;

ALTER TABLE delegation_chains ENABLE ROW LEVEL SECURITY;
ALTER TABLE delegation_chains FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON delegation_chains
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);
