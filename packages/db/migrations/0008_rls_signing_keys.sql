ALTER TABLE workspace_signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_signing_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON workspace_signing_keys
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON workspace_signing_keys TO pact_app;
