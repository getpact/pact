-- Wrap session var in NULLIF so an unset or empty value cleanly fails RLS
-- instead of raising "invalid input syntax for type uuid".

DO $$
DECLARE
  t TEXT;
  tenant_tables TEXT[] := ARRAY[
    'users', 'roles', 'groups',
    'policies', 'refresh_tokens', 'revoked_jtis', 'invites',
    'vault_secrets', 'adapter_configs', 'brains',
    'audit_events', 'audit_chain_state'
  ];
BEGIN
  FOREACH t IN ARRAY tenant_tables LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (workspace_id = NULLIF(current_setting(''app.current_workspace_id'', true), '''')::uuid)',
      t
    );
  END LOOP;
END
$$;

DROP POLICY IF EXISTS tenant_isolation ON user_roles;
CREATE POLICY tenant_isolation ON user_roles
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = user_roles.user_id
        AND u.workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
    )
  );

DROP POLICY IF EXISTS tenant_isolation ON group_members;
CREATE POLICY tenant_isolation ON group_members
  USING (
    EXISTS (
      SELECT 1 FROM groups g
      WHERE g.id = group_members.group_id
        AND g.workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid
    )
  );
