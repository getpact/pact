ALTER TABLE "refresh_tokens" ADD COLUMN "audience" text DEFAULT 'pact-mcp' NOT NULL;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "access_jti" text;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "revoked_at" timestamp with time zone;--> statement-breakpoint
CREATE INDEX "refresh_tokens_access_jti_idx" ON "refresh_tokens" USING btree ("workspace_id","access_jti");
