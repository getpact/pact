CREATE TABLE IF NOT EXISTS agents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  slug text NOT NULL,
  display_name text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('service', 'user_delegated', 'sub_agent')),
  owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  pubkey_jwk jsonb NOT NULL,
  pubkey_thumbprint text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  revoked_at timestamp with time zone
);

CREATE UNIQUE INDEX IF NOT EXISTS agents_workspace_slug_idx
  ON agents(workspace_id, slug);

CREATE UNIQUE INDEX IF NOT EXISTS agents_workspace_thumbprint_idx
  ON agents(workspace_id, pubkey_thumbprint)
  WHERE revoked_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON agents TO pact_app;

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON agents
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);
