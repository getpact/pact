CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS brain_pages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  source_uri text NOT NULL,
  source_kind text NOT NULL,
  content_hash bytea NOT NULL,
  title text,
  author_user_id uuid REFERENCES users(id),
  audience text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CHECK (source_kind IN ('manual', 'connector'))
);

CREATE UNIQUE INDEX IF NOT EXISTS brain_pages_workspace_source_hash_idx
  ON brain_pages(workspace_id, source_uri, content_hash)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS brain_pages_workspace_idx
  ON brain_pages(workspace_id)
  WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS brain_chunks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  page_id uuid NOT NULL REFERENCES brain_pages(id) ON DELETE CASCADE,
  chunk_index int NOT NULL,
  content text NOT NULL,
  content_sha256 bytea NOT NULL,
  token_count int,
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS brain_chunks_page_idx_uq
  ON brain_chunks(page_id, chunk_index)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS brain_chunks_workspace_idx
  ON brain_chunks(workspace_id)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS brain_chunks_fts_idx
  ON brain_chunks
  USING gin (to_tsvector('english', content))
  WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS brain_chunk_embeddings (
  chunk_id uuid PRIMARY KEY REFERENCES brain_chunks(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  model text NOT NULL,
  embedding vector(1536) NOT NULL,
  embedded_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS brain_chunk_embeddings_workspace_idx
  ON brain_chunk_embeddings(workspace_id);

CREATE INDEX IF NOT EXISTS brain_chunk_embeddings_hnsw
  ON brain_chunk_embeddings
  USING hnsw (embedding vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);

GRANT SELECT, INSERT, UPDATE, DELETE ON brain_pages TO pact_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON brain_chunks TO pact_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON brain_chunk_embeddings TO pact_app;

ALTER TABLE brain_pages ENABLE ROW LEVEL SECURITY;
ALTER TABLE brain_pages FORCE ROW LEVEL SECURITY;
ALTER TABLE brain_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE brain_chunks FORCE ROW LEVEL SECURITY;
ALTER TABLE brain_chunk_embeddings ENABLE ROW LEVEL SECURITY;
ALTER TABLE brain_chunk_embeddings FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON brain_pages
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);

CREATE POLICY tenant_isolation ON brain_chunks
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);

CREATE POLICY tenant_isolation ON brain_chunk_embeddings
  USING (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.current_workspace_id', true), '')::uuid);
