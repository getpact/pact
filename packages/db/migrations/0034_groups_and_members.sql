-- Extend groups and group_members so memberships can be soft-revoked and
-- tenant isolation on group_members can use a direct workspace_id check
-- instead of an EXISTS subquery against groups.

ALTER TABLE groups
  ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE groups
  ADD COLUMN IF NOT EXISTS revoked_at timestamptz;

CREATE INDEX IF NOT EXISTS groups_workspace_active_idx
  ON groups(workspace_id) WHERE revoked_at IS NULL;

ALTER TABLE group_members
  ADD COLUMN IF NOT EXISTS id uuid;

UPDATE group_members SET id = gen_random_uuid() WHERE id IS NULL;

ALTER TABLE group_members
  ALTER COLUMN id SET DEFAULT gen_random_uuid(),
  ALTER COLUMN id SET NOT NULL;

ALTER TABLE group_members
  ADD COLUMN IF NOT EXISTS workspace_id uuid REFERENCES workspaces(id) ON DELETE CASCADE;

UPDATE group_members gm
   SET workspace_id = g.workspace_id
  FROM groups g
 WHERE g.id = gm.group_id
   AND gm.workspace_id IS NULL;

ALTER TABLE group_members
  ALTER COLUMN workspace_id SET NOT NULL;

ALTER TABLE group_members
  ADD COLUMN IF NOT EXISTS added_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE group_members
  ADD COLUMN IF NOT EXISTS revoked_at timestamptz;

CREATE INDEX IF NOT EXISTS group_members_user_active_idx
  ON group_members(workspace_id, user_id) WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS group_members_group_active_idx
  ON group_members(workspace_id, group_id) WHERE revoked_at IS NULL;

DROP POLICY IF EXISTS tenant_isolation ON group_members;
CREATE POLICY tenant_isolation ON group_members
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);
