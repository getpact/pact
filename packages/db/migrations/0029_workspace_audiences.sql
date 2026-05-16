CREATE TABLE IF NOT EXISTS workspace_audiences (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name text NOT NULL,
  description text,
  allowed_subject_patterns text[] NOT NULL DEFAULT '{}',
  created_by_user_id uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE UNIQUE INDEX workspace_audiences_unique_name
  ON workspace_audiences(workspace_id, name)
  WHERE revoked_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON workspace_audiences TO pact_app;

ALTER TABLE workspace_audiences ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_audiences FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON workspace_audiences
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);
