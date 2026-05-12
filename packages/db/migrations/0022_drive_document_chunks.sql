CREATE TABLE IF NOT EXISTS drive_document_chunks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  file_id text NOT NULL,
  file_name text,
  mime_type text,
  modified_time timestamp with time zone,
  chunk_index integer NOT NULL,
  content text NOT NULL,
  content_sha256 text NOT NULL,
  indexed_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS drive_document_chunks_unique_idx
  ON drive_document_chunks(workspace_id, user_id, file_id, chunk_index);

CREATE INDEX IF NOT EXISTS drive_document_chunks_workspace_user_idx
  ON drive_document_chunks(workspace_id, user_id);

CREATE INDEX IF NOT EXISTS drive_document_chunks_file_idx
  ON drive_document_chunks(workspace_id, user_id, file_id);

CREATE INDEX IF NOT EXISTS drive_document_chunks_fts_idx
  ON drive_document_chunks
  USING gin (to_tsvector('english', content));

GRANT SELECT, INSERT, UPDATE, DELETE ON drive_document_chunks TO pact_app;

ALTER TABLE drive_document_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE drive_document_chunks FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON drive_document_chunks
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);
