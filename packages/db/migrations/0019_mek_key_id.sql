ALTER TABLE "workspace_signing_keys" ADD COLUMN IF NOT EXISTS "mek_key_id" text;
ALTER TABLE "vault_secrets" ADD COLUMN IF NOT EXISTS "mek_key_id" text;
CREATE INDEX IF NOT EXISTS "workspace_signing_keys_mek_key_id_idx"
  ON "workspace_signing_keys" ("mek_key_id");
CREATE INDEX IF NOT EXISTS "vault_secrets_mek_key_id_idx"
  ON "vault_secrets" ("mek_key_id");
