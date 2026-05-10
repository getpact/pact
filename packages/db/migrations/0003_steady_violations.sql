CREATE TABLE "audit_chain_state" (
	"workspace_id" uuid PRIMARY KEY NOT NULL,
	"last_hash" text NOT NULL,
	"last_event_id" uuid,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"workspace_id" uuid NOT NULL,
	"ts" timestamp with time zone DEFAULT now() NOT NULL,
	"actor_kind" text NOT NULL,
	"actor_id" text,
	"action" text NOT NULL,
	"target" jsonb NOT NULL,
	"decision" text NOT NULL,
	"supporting" jsonb,
	"signing_key_id" text NOT NULL,
	"prev_hash" text NOT NULL,
	"this_hash" text NOT NULL,
	"signature" text NOT NULL
);
--> statement-breakpoint
ALTER TABLE "audit_chain_state" ADD CONSTRAINT "audit_chain_state_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_workspace_id_workspaces_id_fk" FOREIGN KEY ("workspace_id") REFERENCES "public"."workspaces"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_events_workspace_ts_idx" ON "audit_events" USING btree ("workspace_id","ts");--> statement-breakpoint
CREATE INDEX "audit_events_workspace_action_idx" ON "audit_events" USING btree ("workspace_id","action");