-- Application role that respects RLS. Tables stay owned by the migration role.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pact_app') THEN
    CREATE ROLE pact_app NOLOGIN NOBYPASSRLS;
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO pact_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pact_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO pact_app;

-- Enable RLS and isolation policy on every tenant-scoped table.
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
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (workspace_id = current_setting(''app.current_workspace_id'', true)::uuid)',
      t
    );
  END LOOP;
END
$$;

-- user_roles and group_members do not carry workspace_id. Use join-style policies.
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON user_roles
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = user_roles.user_id
        AND u.workspace_id = current_setting('app.current_workspace_id', true)::uuid
    )
  );

ALTER TABLE group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_members FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON group_members
  USING (
    EXISTS (
      SELECT 1 FROM groups g
      WHERE g.id = group_members.group_id
        AND g.workspace_id = current_setting('app.current_workspace_id', true)::uuid
    )
  );
