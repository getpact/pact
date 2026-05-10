import { defineConfig } from "drizzle-kit";

const url = process.env.DATABASE_URL ?? "postgres://pact:pact@localhost:5432/pact";

export default defineConfig({
  schema: "./src/schema.ts",
  out: "./migrations",
  dialect: "postgresql",
  dbCredentials: { url },
  strict: true,
  verbose: true,
});
