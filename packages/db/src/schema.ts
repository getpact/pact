import { sql } from "drizzle-orm";
import {
  type AnyPgColumn,
  bigint,
  check,
  customType,
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

const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return "bytea";
  },
});

const vector1536 = customType<{ data: number[]; driverData: string }>({
  dataType() {
    return "vector(1536)";
  },
  toDriver(value) {
    return `[${value.join(",")}]`;
  },
  fromDriver(value) {
    if (typeof value !== "string") return [];
    const trimmed = value.replace(/^\[/, "").replace(/\]$/, "");
    if (trimmed.length === 0) return [];
    return trimmed.split(",").map((v) => Number(v));
  },
});

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
    googleSub: text("google_sub"),
    name: text("name"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("users_workspace_email_idx").on(t.workspaceId, t.email),
    uniqueIndex("users_workspace_google_sub_idx")
      .on(t.workspaceId, t.googleSub)
      .where(sql`google_sub IS NOT NULL`),
  ],
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
    familyId: uuid("family_id").notNull().defaultRandom(),
    parentId: uuid("parent_id").references((): AnyPgColumn => refreshTokens.id, {
      onDelete: "set null",
    }),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index("refresh_tokens_user_idx").on(t.userId),
    index("refresh_tokens_access_jti_idx").on(t.workspaceId, t.accessJti),
    index("refresh_tokens_family_idx").on(t.workspaceId, t.familyId),
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
    mekKeyId: text("mek_key_id"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    rotatedAt: timestamp("rotated_at", { withTimezone: true }),
  },
  (t) => [
    uniqueIndex("vault_secrets_workspace_kind_target_idx").on(t.workspaceId, t.kind, t.target),
    index("vault_secrets_mek_key_id_idx").on(t.mekKeyId),
  ],
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
    status: text("status").notNull().default("active"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index("brains_workspace_idx").on(t.workspaceId),
    uniqueIndex("brains_workspace_kind_idx")
      .on(t.workspaceId, t.kind)
      .where(sql`status = 'active'`),
  ],
);

export type VaultSecret = typeof vaultSecrets.$inferSelect;
export type NewVaultSecret = typeof vaultSecrets.$inferInsert;

export const workspaceOauthConnections = pgTable(
  "workspace_oauth_connections",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    provider: text("provider").notNull(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    providerSubject: text("provider_subject").notNull(),
    email: text("email").notNull(),
    scopes: jsonb("scopes").notNull(),
    status: text("status").notNull().default("connected"),
    vaultTarget: text("vault_target").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    connectedAt: timestamp("connected_at", { withTimezone: true }).notNull().defaultNow(),
    lastRefreshAt: timestamp("last_refresh_at", { withTimezone: true }),
    lastError: text("last_error"),
    disconnectedAt: timestamp("disconnected_at", { withTimezone: true }),
  },
  (t) => [
    uniqueIndex("workspace_oauth_connections_active_idx")
      .on(t.workspaceId, t.provider, t.userId)
      .where(sql`disconnected_at IS NULL`),
    index("workspace_oauth_connections_workspace_provider_idx").on(t.workspaceId, t.provider),
    check(
      "workspace_oauth_connections_status_check",
      sql`${t.status} IN ('connected', 'disconnected', 'expired')`,
    ),
  ],
);

export type WorkspaceOauthConnection = typeof workspaceOauthConnections.$inferSelect;
export type NewWorkspaceOauthConnection = typeof workspaceOauthConnections.$inferInsert;

export const driveDocumentChunks = pgTable(
  "drive_document_chunks",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    fileId: text("file_id").notNull(),
    fileName: text("file_name"),
    mimeType: text("mime_type"),
    modifiedTime: timestamp("modified_time", { withTimezone: true }),
    chunkIndex: integer("chunk_index").notNull(),
    content: text("content").notNull(),
    contentSha256: text("content_sha256").notNull(),
    indexedAt: timestamp("indexed_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("drive_document_chunks_unique_idx").on(
      t.workspaceId,
      t.userId,
      t.fileId,
      t.chunkIndex,
    ),
    index("drive_document_chunks_workspace_user_idx").on(t.workspaceId, t.userId),
    index("drive_document_chunks_file_idx").on(t.workspaceId, t.userId, t.fileId),
  ],
);

export type DriveDocumentChunk = typeof driveDocumentChunks.$inferSelect;
export type NewDriveDocumentChunk = typeof driveDocumentChunks.$inferInsert;

export const brainPages = pgTable(
  "brain_pages",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    sourceUri: text("source_uri").notNull(),
    sourceKind: text("source_kind").notNull(),
    contentHash: bytea("content_hash").notNull(),
    title: text("title"),
    authorUserId: uuid("author_user_id").references(() => users.id),
    audience: text("audience").array().notNull().default(sql`'{}'`),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
    deletedAt: timestamp("deleted_at", { withTimezone: true }),
  },
  (t) => [
    uniqueIndex("brain_pages_workspace_source_hash_idx")
      .on(t.workspaceId, t.sourceUri, t.contentHash)
      .where(sql`deleted_at IS NULL`),
    index("brain_pages_workspace_idx").on(t.workspaceId).where(sql`deleted_at IS NULL`),
    check("brain_pages_source_kind_check", sql`${t.sourceKind} IN ('manual', 'connector')`),
  ],
);

export const brainChunks = pgTable(
  "brain_chunks",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    pageId: uuid("page_id")
      .notNull()
      .references(() => brainPages.id, { onDelete: "cascade" }),
    chunkIndex: integer("chunk_index").notNull(),
    content: text("content").notNull(),
    contentSha256: bytea("content_sha256").notNull(),
    tokenCount: integer("token_count"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    deletedAt: timestamp("deleted_at", { withTimezone: true }),
  },
  (t) => [
    uniqueIndex("brain_chunks_page_idx_uq")
      .on(t.pageId, t.chunkIndex)
      .where(sql`deleted_at IS NULL`),
    index("brain_chunks_workspace_idx").on(t.workspaceId).where(sql`deleted_at IS NULL`),
  ],
);

export const brainChunkEmbeddings = pgTable(
  "brain_chunk_embeddings",
  {
    chunkId: uuid("chunk_id")
      .primaryKey()
      .references(() => brainChunks.id, { onDelete: "cascade" }),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    model: text("model").notNull(),
    embedding: vector1536("embedding").notNull(),
    embeddedAt: timestamp("embedded_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("brain_chunk_embeddings_workspace_idx").on(t.workspaceId)],
);

export type BrainPage = typeof brainPages.$inferSelect;
export type NewBrainPage = typeof brainPages.$inferInsert;
export type BrainChunk = typeof brainChunks.$inferSelect;
export type NewBrainChunk = typeof brainChunks.$inferInsert;
export type BrainChunkEmbedding = typeof brainChunkEmbeddings.$inferSelect;
export type NewBrainChunkEmbedding = typeof brainChunkEmbeddings.$inferInsert;

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
    mekKeyId: text("mek_key_id"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    validForSigningUntil: timestamp("valid_for_signing_until", { withTimezone: true }),
    validForVerificationUntil: timestamp("valid_for_verification_until", { withTimezone: true }),
  },
  (t) => [
    index("workspace_signing_keys_workspace_kind_idx").on(t.workspaceId, t.kind),
    index("workspace_signing_keys_mek_key_id_idx").on(t.mekKeyId),
  ],
);

export type WorkspaceSigningKey = typeof workspaceSigningKeys.$inferSelect;
export type NewWorkspaceSigningKey = typeof workspaceSigningKeys.$inferInsert;

export const agents = pgTable(
  "agents",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    slug: text("slug").notNull(),
    displayName: text("display_name").notNull(),
    kind: text("kind").notNull(),
    ownerUserId: uuid("owner_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    pubkeyJwk: jsonb("pubkey_jwk").notNull(),
    pubkeyThumbprint: text("pubkey_thumbprint").notNull(),
    status: text("status").notNull().default("active"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (t) => [
    uniqueIndex("agents_workspace_slug_idx").on(t.workspaceId, t.slug),
    uniqueIndex("agents_workspace_thumbprint_idx")
      .on(t.workspaceId, t.pubkeyThumbprint)
      .where(sql`revoked_at IS NULL`),
    check("agents_kind_check", sql`${t.kind} IN ('service', 'user_delegated', 'sub_agent')`),
    check("agents_status_check", sql`${t.status} IN ('active', 'suspended', 'revoked')`),
  ],
);

export type Agent = typeof agents.$inferSelect;
export type NewAgent = typeof agents.$inferInsert;

export const agentCapabilityGrants = pgTable(
  "agent_capability_grants",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    agentId: uuid("agent_id")
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    onBehalfOfUserId: uuid("on_behalf_of_user_id").references(() => users.id, {
      onDelete: "cascade",
    }),
    onBehalfOfPattern: text("on_behalf_of_pattern"),
    toolName: text("tool_name").notNull(),
    scope: jsonb("scope").notNull(),
    maxUsesPerDay: integer("max_uses_per_day").notNull().default(1000),
    defaultExpTtlSeconds: integer("default_exp_ttl_seconds").notNull().default(300),
    audience: text("audience").array().notNull().default(sql`'{}'`),
    policyVersion: integer("policy_version").notNull().default(1),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (t) => [
    index("agent_capability_grants_agent_tool_idx")
      .on(t.workspaceId, t.agentId, t.toolName)
      .where(sql`revoked_at IS NULL`),
    index("agent_capability_grants_scope_gin").using("gin", sql`${t.scope} jsonb_path_ops`),
    check(
      "agent_capability_grants_on_behalf_of_check",
      sql`${t.onBehalfOfUserId} IS NOT NULL OR ${t.onBehalfOfPattern} IS NOT NULL`,
    ),
  ],
);

export type AgentCapabilityGrant = typeof agentCapabilityGrants.$inferSelect;
export type NewAgentCapabilityGrant = typeof agentCapabilityGrants.$inferInsert;

export const agentInvocations = pgTable(
  "agent_invocations",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    jti: uuid("jti").notNull(),
    parentJti: uuid("parent_jti"),
    agentId: uuid("agent_id").references(() => agents.id, { onDelete: "set null" }),
    agentIdSnapshot: uuid("agent_id_snapshot"),
    grantId: uuid("grant_id").references(() => agentCapabilityGrants.id, { onDelete: "set null" }),
    onBehalfOfUserId: uuid("on_behalf_of_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    onBehalfOfUserIdSnapshot: uuid("on_behalf_of_user_id_snapshot"),
    toolName: text("tool_name").notNull(),
    scopeClaim: jsonb("scope_claim").notNull(),
    audience: text("audience").notNull(),
    intentJti: text("intent_jti"),
    cnfThumbprint: text("cnf_thumbprint").notNull(),
    redeemStatus: text("redeem_status").notNull(),
    redeemCount: integer("redeem_count").notNull().default(0),
    maxRedeems: integer("max_redeems").notNull().default(1),
    issuedAt: timestamp("issued_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    lastRedeemedAt: timestamp("last_redeemed_at", { withTimezone: true }),
    denyReason: text("deny_reason"),
    auditEventId: uuid("audit_event_id"),
  },
  (t) => [
    uniqueIndex("agent_invocations_workspace_jti_idx").on(t.workspaceId, t.jti),
    index("agent_invocations_agent_time_idx").on(t.workspaceId, t.agentId, t.issuedAt.desc()),
    index("agent_invocations_agent_snapshot_idx").on(
      t.workspaceId,
      t.agentIdSnapshot,
      t.issuedAt.desc(),
    ),
    index("agent_invocations_parent_jti_idx")
      .on(t.workspaceId, t.parentJti)
      .where(sql`parent_jti IS NOT NULL`),
    index("agent_invocations_active_idx")
      .on(t.workspaceId, t.expiresAt)
      .where(sql`redeem_status = 'issued'`),
    index("agent_invocations_scope_gin").using("gin", sql`${t.scopeClaim} jsonb_path_ops`),
    check(
      "agent_invocations_redeem_status_check",
      sql`${t.redeemStatus} IN ('issued', 'redeemed', 'denied', 'expired', 'revoked')`,
    ),
  ],
);

export type AgentInvocation = typeof agentInvocations.$inferSelect;
export type NewAgentInvocation = typeof agentInvocations.$inferInsert;

export const delegationChains = pgTable(
  "delegation_chains",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    parentJti: uuid("parent_jti").notNull(),
    childJti: uuid("child_jti").notNull(),
    parentAgentId: uuid("parent_agent_id")
      .notNull()
      .references(() => agents.id),
    childAgentId: uuid("child_agent_id")
      .notNull()
      .references(() => agents.id),
    scopeReduction: jsonb("scope_reduction").notNull(),
    depth: integer("depth").notNull(),
    maxDepth: integer("max_depth").notNull().default(3),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("delegation_chains_child_jti_idx").on(t.workspaceId, t.childJti),
    index("delegation_chains_parent_jti_idx").on(t.workspaceId, t.parentJti),
    check("delegation_chains_depth_max_check", sql`${t.depth} <= ${t.maxDepth}`),
    check("delegation_chains_depth_positive_check", sql`${t.depth} > 0`),
  ],
);

export type DelegationChain = typeof delegationChains.$inferSelect;
export type NewDelegationChain = typeof delegationChains.$inferInsert;

export const workspaceAudiences = pgTable(
  "workspace_audiences",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    description: text("description"),
    allowedSubjectPatterns: text("allowed_subject_patterns").array().notNull().default(sql`'{}'`),
    createdByUserId: uuid("created_by_user_id").references(() => users.id),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (t) => [
    uniqueIndex("workspace_audiences_unique_name")
      .on(t.workspaceId, t.name)
      .where(sql`revoked_at IS NULL`),
  ],
);

export type WorkspaceAudience = typeof workspaceAudiences.$inferSelect;
export type NewWorkspaceAudience = typeof workspaceAudiences.$inferInsert;

export const kbjwtReplayLog = pgTable(
  "kbjwt_replay_log",
  {
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    jti: uuid("jti").notNull(),
    kbIat: bigint("kb_iat", { mode: "number" }).notNull(),
    sdHash: bytea("sd_hash").notNull(),
    presentedAt: timestamp("presented_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.workspaceId, t.jti, t.kbIat, t.sdHash] }),
    index("kbjwt_replay_log_presented_idx").on(t.workspaceId, t.presentedAt),
  ],
);

export type KbjwtReplayLogEntry = typeof kbjwtReplayLog.$inferSelect;
export type NewKbjwtReplayLogEntry = typeof kbjwtReplayLog.$inferInsert;

export const sendCaps = pgTable(
  "send_caps",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspaces.id, { onDelete: "cascade" }),
    issuerUserId: uuid("issuer_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    granteeUserId: uuid("grantee_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    scopePattern: jsonb("scope_pattern").notNull().default(sql`'{}'::jsonb`),
    maxUses: integer("max_uses"),
    usedCount: integer("used_count").notNull().default(0),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    revokedReason: text("revoked_reason"),
  },
  (t) => [
    index("send_caps_issuer_grantee_idx")
      .on(t.workspaceId, t.issuerUserId, t.granteeUserId)
      .where(sql`revoked_at IS NULL`),
    index("send_caps_grantee_active_idx")
      .on(t.workspaceId, t.granteeUserId, t.expiresAt)
      .where(sql`revoked_at IS NULL`),
    check("send_caps_issuer_grantee_check", sql`${t.issuerUserId} <> ${t.granteeUserId}`),
  ],
);

export type SendCap = typeof sendCaps.$inferSelect;
export type NewSendCap = typeof sendCaps.$inferInsert;
