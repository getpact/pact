import { describe, expect, it } from "vitest";
import { buildTestEnv, createTestWorkspace, issueTestToken, uniqueSlug } from "../index.js";

describe("test helpers", () => {
  it("builds a complete test environment", async () => {
    const env = await buildTestEnv("postgres://localhost/test");
    expect(env.DATABASE_URL).toBe("postgres://localhost/test");
    expect(env.ENVIRONMENT).toBe("test");
    expect(env.ENABLE_DEV_ISSUE).toBe("true");
    expect(env.MEK.length).toBeGreaterThan(0);
  });

  it("creates unique slugs with a prefix", () => {
    expect(uniqueSlug("adm").startsWith("adm-")).toBe(true);
  });

  it("accepts loopback and *.local hosts", async () => {
    for (const url of [
      "postgres://localhost/db",
      "postgres://127.0.0.1:5432/db",
      "postgres://0.0.0.0/db",
      "postgres://db.local/db",
    ]) {
      const env = await buildTestEnv(url);
      expect(env.PACT_ALLOW_UNAUTHED_WORKSPACE_CREATE).toBe("true");
    }
  });

  it("refuses workspace bypass against non-local database", async () => {
    for (const url of [
      "postgres://db.prod.example.com/pact",
      "postgres://10.0.0.5:5432/pact",
      "postgres://test",
    ]) {
      await expect(buildTestEnv(url)).rejects.toThrow(/non-test database/);
    }
  });

  it("refuses workspace bypass under NODE_ENV=production", async () => {
    const prev = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      await expect(buildTestEnv("postgres://localhost/db")).rejects.toThrow(/production/);
    } finally {
      if (prev === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = prev;
    }
  });

  it("throws response details when workspace creation fails", async () => {
    const env = await buildTestEnv("postgres://localhost/test");
    await expect(
      createTestWorkspace({ request: () => new Response("bad", { status: 500 }) }, env, {
        slug: "x",
        adminEmail: "a@example.com",
      }),
    ).rejects.toThrow("workspace create failed (500): bad");
  });

  it("throws response details when token issuance fails", async () => {
    const env = await buildTestEnv("postgres://localhost/test");
    await expect(
      issueTestToken({ request: () => new Response("bad", { status: 403 }) }, env, {
        workspaceId: "ws",
        email: "a@example.com",
        audience: "pact-admin",
      }),
    ).rejects.toThrow("token issue failed (403): bad");
  });
});
