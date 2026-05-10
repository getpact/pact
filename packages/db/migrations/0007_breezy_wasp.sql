CREATE TABLE "workspace_signing_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"alg" text DEFAULT 'EdDSA' NOT NULL,
	"public_key_spki" text NOT NULL,
	"private_key_wrapped" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"valid_for_signing_until" timestamp with time zone,
	"valid_for_verification_until" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "workspace_signing_keys" ADD CONSTRAINT "workspace_signing_keys_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "workspace_signing_keys_workspace_kind_idx" ON "workspace_signing_keys" USING btree ("workspace_id","kind");