import { describe, expect, it } from "vitest";
import { buildTestEnv, createTestWorkspace, issueTestToken, uniqueSlug } from "../index.js";

describe("test helpers", () => {
  it("builds a complete test environment", async () => {
    const env = await buildTestEnv("postgres://test");
    expect(env.DATABASE_URL).toBe("postgres://test");
    expect(env.ENVIRONMENT).toBe("test");
    expect(env.ENABLE_DEV_ISSUE).toBe("true");
    expect(env.MEK.length).toBeGreaterThan(0);
  });

  it("creates unique slugs with a prefix", () => {
    expect(uniqueSlug("adm").startsWith("adm-")).toBe(true);
  });

  it("throws response details when workspace creation fails", async () => {
    const env = await buildTestEnv("postgres://test");
    await expect(
      createTestWorkspace({ request: () => new Response("bad", { status: 500 }) }, env, {
        slug: "x",
        adminEmail: "a@example.com",
      }),
    ).rejects.toThrow("workspace create failed (500): bad");
  });

  it("throws response details when token issuance fails", async () => {
    const env = await buildTestEnv("postgres://test");
    await expect(
      issueTestToken({ request: () => new Response("bad", { status: 403 }) }, env, {
        workspaceId: "ws",
        email: "a@example.com",
        audience: "pact-admin",
      }),
    ).rejects.toThrow("token issue failed (403): bad");
  });
});
