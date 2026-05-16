CREATE TABLE IF NOT EXISTS kbjwt_replay_log (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  jti uuid NOT NULL,
  kb_iat bigint NOT NULL,
  sd_hash bytea NOT NULL,
  presented_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, jti, kb_iat, sd_hash)
);

CREATE INDEX kbjwt_replay_log_presented_idx
  ON kbjwt_replay_log(workspace_id, presented_at);

-- Cleanup policy note: rows older than 24h whose linked agent_invocations
-- have also expired are safe to delete. A scheduled purge job is deferred;
-- the primary key prevents the table from accepting duplicate replays
-- regardless of how long entries are retained.

GRANT SELECT, INSERT, DELETE ON kbjwt_replay_log TO pact_app;

ALTER TABLE kbjwt_replay_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE kbjwt_replay_log FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON kbjwt_replay_log
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);
