CREATE TABLE IF NOT EXISTS send_caps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  issuer_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  grantee_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope_pattern jsonb NOT NULL DEFAULT '{}'::jsonb,
  max_uses int,
  used_count int NOT NULL DEFAULT 0,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  revoked_reason text,
  CHECK (issuer_user_id != grantee_user_id)
);

CREATE INDEX send_caps_issuer_grantee_idx
  ON send_caps(workspace_id, issuer_user_id, grantee_user_id)
  WHERE revoked_at IS NULL;

CREATE INDEX send_caps_grantee_active_idx
  ON send_caps(workspace_id, grantee_user_id, expires_at)
  WHERE revoked_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON send_caps TO pact_app;

ALTER TABLE send_caps ENABLE ROW LEVEL SECURITY;
ALTER TABLE send_caps FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON send_caps
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);
