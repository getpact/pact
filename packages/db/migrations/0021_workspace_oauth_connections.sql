CREATE TABLE IF NOT EXISTS workspace_oauth_connections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  provider text NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_subject text NOT NULL,
  email text NOT NULL,
  scopes jsonb NOT NULL,
  status text NOT NULL DEFAULT 'connected' CHECK (status IN ('connected', 'disconnected', 'expired')),
  vault_target text NOT NULL,
  expires_at timestamp with time zone,
  connected_at timestamp with time zone NOT NULL DEFAULT now(),
  last_refresh_at timestamp with time zone,
  last_error text,
  disconnected_at timestamp with time zone
);

CREATE UNIQUE INDEX IF NOT EXISTS workspace_oauth_connections_active_idx
  ON workspace_oauth_connections(workspace_id, provider, user_id)
  WHERE disconnected_at IS NULL;

CREATE INDEX IF NOT EXISTS workspace_oauth_connections_workspace_provider_idx
  ON workspace_oauth_connections(workspace_id, provider);

GRANT SELECT, INSERT, UPDATE, DELETE ON workspace_oauth_connections TO pact_app;

ALTER TABLE workspace_oauth_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_oauth_connections FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON workspace_oauth_connections
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);
