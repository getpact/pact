import { sql } from "drizzle-orm";
import {
  bigint,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

export const workspaces = pgTable(
  "workspaces",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    slug: text("slug").notNull(),
    name: text("name").notNull(),
    region: text("region").notNull().default("us-east-1"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("workspaces_slug_idx").on(t.slug)],
);

export const users = pgTable(
  "users",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    email: text("email").notNull(),
    name: text("name"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("users_workspace_email_idx").on(t.workspaceId, t.email)],
);

export const roles = pgTable(
  "roles",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    description: text("description"),
  },
  (t) => [uniqueIndex("roles_workspace_name_idx").on(t.workspaceId, t.name)],
);

export const userRoles = pgTable(
  "user_roles",
  {
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    roleId: uuid("role_id")
      .notNull()
      .references(() => roles.id, { onDelete: "cascade" }),
  },
  (t) => [primaryKey({ columns: [t.userId, t.roleId] })],
);

export const groups = pgTable(
  "groups",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    description: text("description"),
  },
  (t) => [uniqueIndex("groups_workspace_name_idx").on(t.workspaceId, t.name)],
);

export const groupMembers = pgTable(
  "group_members",
  {
    groupId: uuid("group_id")
      .notNull()
      .references(() => groups.id, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
  },
  (t) => [primaryKey({ columns: [t.groupId, t.userId] })],
);

export const policies = pgTable(
  "policies",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    version: integer("version").notNull(),
    body: jsonb("body").notNull(),
    createdBy: uuid("created_by")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    replacedAt: timestamp("replaced_at", { withTimezone: true }),
  },
  (t) => [
    index("policies_workspace_replaced_idx").on(t.workspaceId, t.replacedAt),
    uniqueIndex("policies_workspace_version_idx").on(t.workspaceId, t.version),
    uniqueIndex("policies_workspace_active_idx").on(t.workspaceId).where(sql`replaced_at IS NULL`),
  ],
);

export const refreshTokens = pgTable(
  "refresh_tokens",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    ciphertext: text("ciphertext").notNull(),
    audience: text("audience").notNull().default("pact-mcp"),
    accessJti: text("access_jti"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index("refresh_tokens_user_idx").on(t.userId),
    index("refresh_tokens_access_jti_idx").on(t.workspaceId, t.accessJti),
  ],
);

export const revokedJtis = pgTable(
  "revoked_jtis",
  {
    jti: text("jti").notNull(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }).notNull().defaultNow(),
    revokedBy: uuid("revoked_by").references(() => users.id, { onDelete: "set null" }),
    reason: text("reason"),
  },
  (t) => [primaryKey({ columns: [t.workspaceId, t.jti] })],
);

export const invites = pgTable(
  "invites",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    email: text("email").notNull(),
    scope: jsonb("scope").notNull(),
    ttl: text("ttl").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdBy: uuid("created_by")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    status: text("status").notNull().default("pending"),
  },
  (t) => [index("invites_email_idx").on(t.email)],
);

export type Workspace = typeof workspaces.$inferSelect;
export type NewWorkspace = typeof workspaces.$inferInsert;
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Role = typeof roles.$inferSelect;
export type NewRole = typeof roles.$inferInsert;
export type Group = typeof groups.$inferSelect;
export type NewGroup = typeof groups.$inferInsert;
export type Policy = typeof policies.$inferSelect;
export type NewPolicy = typeof policies.$inferInsert;
export type RefreshToken = typeof refreshTokens.$inferSelect;
export type NewRefreshToken = typeof refreshTokens.$inferInsert;
export type RevokedJti = typeof revokedJtis.$inferSelect;
export type NewRevokedJti = typeof revokedJtis.$inferInsert;
export type Invite = typeof invites.$inferSelect;
export type NewInvite = typeof invites.$inferInsert;

export const vaultSecrets = pgTable(
  "vault_secrets",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    kind: text("kind").notNull(),
    target: text("target").notNull(),
    ciphertext: text("ciphertext").notNull(),
    dekCiphertext: text("dek_ciphertext").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    rotatedAt: timestamp("rotated_at", { withTimezone: true }),
  },
  (t) => [
    uniqueIndex("vault_secrets_workspace_kind_target_idx").on(t.workspaceId, t.kind, t.target),
  ],
);

export const adapterConfigs = pgTable(
  "adapter_configs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    kind: text("kind").notNull(),
    config: jsonb("config").notNull(),
    status: text("status").notNull().default("active"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("adapter_configs_workspace_kind_idx").on(t.workspaceId, t.kind)],
);

export const brains = pgTable(
  "brains",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    kind: text("kind").notNull(),
    baseUrl: text("base_url").notNull(),
    authScheme: text("auth_scheme").notNull(),
    scopeInjectionTemplate: jsonb("scope_injection_template").notNull(),
    responseFilter: jsonb("response_filter"),
    status: text("status").notNull().default("active"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("brains_workspace_idx").on(t.workspaceId)],
);

export type VaultSecret = typeof vaultSecrets.$inferSelect;
export type NewVaultSecret = typeof vaultSecrets.$inferInsert;
export type AdapterConfig = typeof adapterConfigs.$inferSelect;
export type NewAdapterConfig = typeof adapterConfigs.$inferInsert;
export type Brain = typeof brains.$inferSelect;
export type NewBrain = typeof brains.$inferInsert;

export const auditEvents = pgTable(
  "audit_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    auditSeq: bigint("audit_seq", { mode: "number" }).notNull(),
    ts: timestamp("ts", { withTimezone: true }).notNull().defaultNow(),
    actorKind: text("actor_kind").notNull(),
    actorId: text("actor_id"),
    action: text("action").notNull(),
    target: jsonb("target").notNull(),
    decision: text("decision").notNull(),
    supporting: jsonb("supporting"),
    signingKeyId: text("signing_key_id").notNull(),
    prevHash: text("prev_hash").notNull(),
    thisHash: text("this_hash").notNull(),
    signature: text("signature").notNull(),
  },
  (t) => [
    uniqueIndex("audit_events_workspace_seq_idx").on(t.workspaceId, t.auditSeq),
    index("audit_events_workspace_ts_idx").on(t.workspaceId, t.ts),
    index("audit_events_workspace_action_idx").on(t.workspaceId, t.action),
  ],
);

export const auditChainState = pgTable("audit_chain_state", {
  workspaceId: uuid("workspace_id")
    .primaryKey()
    .references(() => workspaces.id, { onDelete: "cascade" }),
  lastHash: text("last_hash").notNull(),
  lastEventId: uuid("last_event_id"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export type AuditEvent = typeof auditEvents.$inferSelect;
export type NewAuditEvent = typeof auditEvents.$inferInsert;
export type AuditChainState = typeof auditChainState.$inferSelect;
export type NewAuditChainState = typeof auditChainState.$inferInsert;

export const rateLimitBuckets = pgTable("rate_limit_buckets", {
  key: text("key").primaryKey(),
  count: integer("count").notNull(),
  resetAt: timestamp("reset_at", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export type RateLimitBucket = typeof rateLimitBuckets.$inferSelect;
export type NewRateLimitBucket = typeof rateLimitBuckets.$inferInsert;

export const workspaceSigningKeys = pgTable(
  "workspace_signing_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    kind: text("kind").notNull(),
    alg: text("alg").notNull().default("EdDSA"),
    publicKeySpki: text("public_key_spki").notNull(),
    privateKeyWrapped: text("private_key_wrapped").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    validForSigningUntil: timestamp("valid_for_signing_until", { withTimezone: true }),
    validForVerificationUntil: timestamp("valid_for_verification_until", { withTimezone: true }),
  },
  (t) => [index("workspace_signing_keys_workspace_kind_idx").on(t.workspaceId, t.kind)],
);

export type WorkspaceSigningKey = typeof workspaceSigningKeys.$inferSelect;
export type NewWorkspaceSigningKey = typeof workspaceSigningKeys.$inferInsert;
