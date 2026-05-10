CREATE UNIQUE INDEX "policies_workspace_version_idx" ON "policies" USING btree ("workspace_id","version");--> statement-breakpoint
CREATE UNIQUE INDEX "policies_workspace_active_idx" ON "policies" USING btree ("workspace_id") WHERE replaced_at IS NULL;
