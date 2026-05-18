import { createClient } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { issuerApp as issuer } from "@getpact/test-harness";
import {
  buildTestEnv,
  createTestWorkspace,
  issueTestToken,
  uniqueSlug,
} from "@getpact/test-helpers";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import app from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

run("admin api groups", () => {
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
      slug: uniqueSlug("grp"),
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

  it("creates, lists, adds and removes a member", async () => {
    const { env, created, token } = await setup();
    const envBag = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };

    const create = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/groups`,
      token,
      "POST",
      { name: "eng", description: "engineering" },
      envBag,
    );
    expect(create.status).toBe(201);
    const group = ((await create.json()) as { group: { id: string; name: string } }).group;
    expect(group.name).toBe("eng");

    const list = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/groups`,
      token,
      "GET",
      undefined,
      envBag,
    );
    expect(list.status).toBe(200);
    const listed = (await list.json()) as { groups: Array<{ id: string; name: string }> };
    expect(listed.groups.find((g) => g.name === "eng")).toBeTruthy();

    const userRes = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/users`,
      token,
      "POST",
      { email: "carol@example.com" },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    const user = ((await userRes.json()) as { user: { id: string } }).user;

    const addByEmail = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/groups/${group.id}/members`,
      token,
      "POST",
      { email: "carol@example.com" },
      envBag,
    );
    expect(addByEmail.status).toBe(201);

    const removeRes = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/groups/${group.id}/members/${user.id}`,
      token,
      "DELETE",
      undefined,
      envBag,
    );
    expect(removeRes.status).toBe(200);

    const removeAgain = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/groups/${group.id}/members/${user.id}`,
      token,
      "DELETE",
      undefined,
      envBag,
    );
    expect(removeAgain.status).toBe(404);
  });

  it("returns 409 on duplicate group name", async () => {
    const { env, created, token } = await setup();
    const envBag = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };
    const first = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/groups`,
      token,
      "POST",
      { name: "dupe" },
      envBag,
    );
    expect(first.status).toBe(201);
    const second = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/groups`,
      token,
      "POST",
      { name: "dupe" },
      envBag,
    );
    expect(second.status).toBe(409);
  });

  it("rejects unknown user when adding a member", async () => {
    const { env, created, token } = await setup();
    const envBag = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };
    const create = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/groups`,
      token,
      "POST",
      { name: "bizdev" },
      envBag,
    );
    const group = ((await create.json()) as { group: { id: string } }).group;
    const res = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/groups/${group.id}/members`,
      token,
      "POST",
      { email: "nobody@example.com" },
      envBag,
    );
    expect(res.status).toBe(404);
  });
});
