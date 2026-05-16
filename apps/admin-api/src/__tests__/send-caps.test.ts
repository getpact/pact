import { createClient, withWorkspace } from "@getpact/db";
import { sendCaps, users, workspaces } from "@getpact/db/schema";
import {
  buildTestEnv,
  createTestWorkspace,
  issueTestToken,
  uniqueSlug,
} from "@getpact/test-helpers";
import { and, eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import issuer from "../../../../apps/issuer/src/index.js";
import app from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

run("send-caps admin api", () => {
  const adminDb = createClient(url as string);
  const cleanup: string[] = [];

  afterEach(async () => {
    while (cleanup.length > 0) {
      const id = cleanup.pop();
      if (!id) continue;
      try {
        await adminDb.delete(workspaces).where(eq(workspaces.id, id));
      } catch {
        // ignore
      }
    }
  });

  const setup = async () => {
    const env = await buildTestEnv(url as string);
    const created = await createTestWorkspace(issuer, env, {
      slug: uniqueSlug("sc"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);
    const issued = await issueTestToken(issuer, env, {
      workspaceId: created.workspaceId,
      email: "alice@example.com",
      audience: env.ADMIN_AUDIENCE,
    });
    const granteeRows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .insert(users)
        .values({ workspaceId: created.workspaceId, email: "bob@example.com" })
        .returning({ id: users.id }),
    );
    const granteeId = granteeRows[0]?.id as string;
    return { env, created, token: issued.token, granteeId };
  };

  const callApi = async (
    suffix: string,
    token: string,
    method: "DELETE" | "GET" | "POST",
    body: unknown,
    workspaceId: string,
    env: { DATABASE_URL: string; MEK: string; ADMIN_AUDIENCE: string },
  ): Promise<Response> => {
    const init: RequestInit = {
      method,
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
    };
    if (body !== undefined) init.body = JSON.stringify(body);
    const path = `/v1/workspaces/${workspaceId}${suffix}`;
    return app.request(path, init, { ISSUER_BASE_URL: "https://issuer.test/acme", ...env });
  };

  it("mints, lists, and revokes a send cap", async () => {
    const { env, created, token, granteeId } = await setup();
    const runtime = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };

    const mint = await callApi(
      "/send-caps",
      token,
      "POST",
      { grantee_user_id: granteeId, max_uses: 3 },
      created.workspaceId,
      runtime,
    );
    expect(mint.status).toBe(201);
    const minted = (await mint.json()) as { send_cap: { id: string; grantee_user_id: string } };
    expect(minted.send_cap.grantee_user_id).toBe(granteeId);

    const list = await callApi(
      "/send-caps?active=true",
      token,
      "GET",
      undefined,
      created.workspaceId,
      runtime,
    );
    expect(list.status).toBe(200);
    const listed = (await list.json()) as { send_caps: Array<{ id: string }> };
    expect(listed.send_caps.map((r) => r.id)).toContain(minted.send_cap.id);

    const revoke = await callApi(
      `/send-caps/${minted.send_cap.id}`,
      token,
      "DELETE",
      { reason: "rotated" },
      created.workspaceId,
      runtime,
    );
    expect(revoke.status).toBe(200);

    const rows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select()
        .from(sendCaps)
        .where(
          and(eq(sendCaps.workspaceId, created.workspaceId), eq(sendCaps.id, minted.send_cap.id)),
        ),
    );
    expect(rows[0]?.revokedAt).not.toBeNull();
    expect(rows[0]?.revokedReason).toBe("rotated");
  });

  it("rejects requests with no admin token as 401", async () => {
    const res = await app.request(
      "/v1/workspaces/11111111-1111-4111-8111-111111111111/send-caps",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({ grantee_user_id: "22222222-2222-4222-8222-222222222222" }),
      },
      {
        DATABASE_URL: url as string,
        MEK: "unused",
        ISSUER_BASE_URL: "https://issuer.test/acme",
        ADMIN_AUDIENCE: "pact-admin",
      },
    );
    expect(res.status).toBe(401);
  });

  it("rejects revoke when caller is not the issuer", async () => {
    const { env, created, token, granteeId } = await setup();
    const runtime = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };

    const mint = await callApi(
      "/send-caps",
      token,
      "POST",
      { grantee_user_id: granteeId },
      created.workspaceId,
      runtime,
    );
    expect(mint.status).toBe(201);
    const minted = (await mint.json()) as { send_cap: { id: string } };

    const granteeToken = await issueTestToken(issuer, env, {
      workspaceId: created.workspaceId,
      email: "bob@example.com",
      audience: env.ADMIN_AUDIENCE,
    });

    const revoke = await callApi(
      `/send-caps/${minted.send_cap.id}`,
      granteeToken.token,
      "DELETE",
      undefined,
      created.workspaceId,
      runtime,
    );
    expect(revoke.status).toBe(403);
  });

  it("isolates send caps across tenants via RLS", async () => {
    const a = await setup();
    const b = await setup();
    const runtimeA = {
      DATABASE_URL: a.env.DATABASE_URL,
      MEK: a.env.MEK,
      ADMIN_AUDIENCE: a.env.ADMIN_AUDIENCE,
    };
    const runtimeB = {
      DATABASE_URL: b.env.DATABASE_URL,
      MEK: b.env.MEK,
      ADMIN_AUDIENCE: b.env.ADMIN_AUDIENCE,
    };

    const mintA = await callApi(
      "/send-caps",
      a.token,
      "POST",
      { grantee_user_id: a.granteeId },
      a.created.workspaceId,
      runtimeA,
    );
    expect(mintA.status).toBe(201);

    const listB = await callApi(
      "/send-caps",
      b.token,
      "GET",
      undefined,
      b.created.workspaceId,
      runtimeB,
    );
    const listedB = (await listB.json()) as { send_caps: Array<{ id: string }> };
    expect(listedB.send_caps).toHaveLength(0);
  });
});
