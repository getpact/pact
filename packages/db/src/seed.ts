import { canonicalizeEmail } from "@getpact/core";
import { createClient } from "./client.js";
import { roles, userRoles, users, workspaces } from "./schema.js";

const url = process.env.DATABASE_URL ?? "postgres://pact:pact@localhost:5432/pact";
const slug = process.env.SEED_WORKSPACE_SLUG ?? "dev";
const email = process.env.SEED_ADMIN_EMAIL ?? "admin@example.com";

const db = createClient(url);

const [workspace] = await db
  .insert(workspaces)
  .values({ slug, name: "Dev Workspace" })
  .onConflictDoNothing({ target: workspaces.slug })
  .returning();

if (!workspace) {
  console.error(`workspace ${slug} already exists, nothing to seed`);
  process.exit(0);
}

const [adminRole] = await db
  .insert(roles)
  .values({ workspaceId: workspace.id, name: "admin", description: "Workspace admin" })
  .returning();

const [user] = await db
  .insert(users)
  .values({ workspaceId: workspace.id, email: canonicalizeEmail(email), name: "Admin" })
  .returning();

if (!adminRole || !user) {
  throw new Error("seed failed: role or user insert returned no row");
}

await db.insert(userRoles).values({ userId: user.id, roleId: adminRole.id });

console.log(`seeded workspace ${workspace.slug} with admin ${user.email}`);
process.exit(0);
