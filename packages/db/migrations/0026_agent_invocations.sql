CREATE TABLE IF NOT EXISTS agent_invocations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  jti uuid NOT NULL,
  parent_jti uuid,
  agent_id uuid NOT NULL REFERENCES agents(id),
  grant_id uuid REFERENCES agent_capability_grants(id),
  on_behalf_of_user_id uuid REFERENCES users(id),
  tool_name text NOT NULL,
  scope_claim jsonb NOT NULL,
  audience text NOT NULL,
  intent_jti text,
  cnf_thumbprint text NOT NULL,
  redeem_status text NOT NULL CHECK (redeem_status IN ('issued', 'redeemed', 'denied', 'expired', 'revoked')),
  redeem_count int NOT NULL DEFAULT 0,
  max_redeems int NOT NULL DEFAULT 1,
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  last_redeemed_at timestamptz,
  deny_reason text,
  audit_event_id uuid
);

CREATE UNIQUE INDEX agent_invocations_workspace_jti_idx
  ON agent_invocations(workspace_id, jti);

CREATE INDEX agent_invocations_agent_time_idx
  ON agent_invocations(workspace_id, agent_id, issued_at DESC);

CREATE INDEX agent_invocations_parent_jti_idx
  ON agent_invocations(workspace_id, parent_jti)
  WHERE parent_jti IS NOT NULL;

CREATE INDEX agent_invocations_active_idx
  ON agent_invocations(workspace_id, expires_at)
  WHERE redeem_status = 'issued';

CREATE INDEX agent_invocations_scope_gin
  ON agent_invocations USING gin (scope_claim jsonb_path_ops);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_invocations TO pact_app;

ALTER TABLE agent_invocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_invocations FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON agent_invocations
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);
