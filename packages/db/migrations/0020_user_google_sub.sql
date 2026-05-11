ALTER TABLE users ADD COLUMN IF NOT EXISTS google_sub text;

CREATE UNIQUE INDEX IF NOT EXISTS users_workspace_google_sub_idx
  ON users(workspace_id, google_sub)
  WHERE google_sub IS NOT NULL;
