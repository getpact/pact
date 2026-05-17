import { createClient } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import {
  buildTestEnv,
  createTestWorkspace,
  issueTestToken,
  uniqueSlug,
} from "@getpact/test-helpers";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import issuer from "../../../../apps/issuer/src/index.js";
import app from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

run("admin api invites", () => {
  const adminDb = createClient(url as string);
  const cleanup: string[] = [];

  afterEach(async () => {
    while (cleanup.length > 0) {
      const id = cleanup.pop();
      if (!id) continue;
      try {
        await adminDb.delete(workspaces).where(eq(workspaces.id, id));
      } catch {}
    }
  });

  const setup = async () => {
    const env = await buildTestEnv(url as string);
    const created = await createTestWorkspace(issuer, env, {
      slug: uniqueSlug("inv"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);
    const issued = await issueTestToken(issuer, env, {
      workspaceId: created.workspaceId,
      email: "alice@example.com",
      audience: env.ADMIN_AUDIENCE,
    });
    return { env, created, token: issued.token };
  };

  const callAdmin = async (
    path: string,
    token: string,
    method: "DELETE" | "GET" | "POST" | "PUT",
    body: unknown,
    env: Record<string, unknown>,
  ) => {
    const init: RequestInit = {
      method,
      headers: { "content-type": "application/json", Authorization: `Bearer ${token}` },
    };
    if (body !== undefined) init.body = JSON.stringify(body);
    return app.request(path, init, {
      ISSUER_BASE_URL: "https://issuer.test/acme",
      ...env,
    });
  };

  it("mints a signed invite, lists it, and soft-revokes it", async () => {
    const { env, created, token } = await setup();
    const envBag = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };

    const mint = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/invites`,
      token,
      "POST",
      { email: "vc@example.com", scope: { doc_id: "deck" }, ttl_seconds: 3600 },
      envBag,
    );
    expect(mint.status).toBe(201);
    const minted = (await mint.json()) as {
      invite_id: string;
      token: string;
      accept_url: string;
    };
    expect(minted.token.split(".")).toHaveLength(3);
    expect(minted.accept_url).toContain("/invite#");

    const list = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/invites`,
      token,
      "GET",
      undefined,
      envBag,
    );
    expect(list.status).toBe(200);
    const listed = (await list.json()) as { invites: Array<{ id: string; email: string }> };
    expect(listed.invites.find((i) => i.id === minted.invite_id)).toBeTruthy();

    const revoke = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/invites/${minted.invite_id}/revoke`,
      token,
      "POST",
      {},
      envBag,
    );
    expect(revoke.status).toBe(200);

    const revokeAgain = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/invites/${minted.invite_id}/revoke`,
      token,
      "POST",
      {},
      envBag,
    );
    expect(revokeAgain.status).toBe(404);
  });

  it("rejects an invite with ttl_seconds below the minimum", async () => {
    const { env, created, token } = await setup();
    const envBag = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };
    const res = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/invites`,
      token,
      "POST",
      { email: "vc@example.com", ttl_seconds: 5 },
      envBag,
    );
    expect(res.status).toBe(400);
  });

  it("rejects an invite with an unknown group id", async () => {
    const { env, created, token } = await setup();
    const envBag = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };
    const res = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/invites`,
      token,
      "POST",
      {
        email: "vc@example.com",
        ttl_seconds: 3600,
        group_ids: ["00000000-0000-0000-0000-000000000000"],
      },
      envBag,
    );
    expect(res.status).toBe(404);
  });
});
