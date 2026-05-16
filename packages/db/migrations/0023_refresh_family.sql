ALTER TABLE "refresh_tokens" ADD COLUMN "family_id" uuid;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD COLUMN "parent_id" uuid REFERENCES "refresh_tokens"("id") ON DELETE SET NULL;--> statement-breakpoint
UPDATE "refresh_tokens" SET "family_id" = "id" WHERE "family_id" IS NULL;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ALTER COLUMN "family_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ALTER COLUMN "family_id" SET DEFAULT gen_random_uuid();--> statement-breakpoint
CREATE INDEX "refresh_tokens_family_idx" ON "refresh_tokens" USING btree ("workspace_id","family_id");
