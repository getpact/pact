-- Add WITH CHECK to workspace_signing_keys so INSERT and UPDATE are also
-- filtered by tenant context, matching other tenant tables.

DROP POLICY IF EXISTS tenant_isolation ON workspace_signing_keys;
CREATE POLICY tenant_isolation ON workspace_signing_keys
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);
