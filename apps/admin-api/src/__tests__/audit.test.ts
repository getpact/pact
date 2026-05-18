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
import { type AuditQueryRow, formatCursor, parseCursor } from "../routes/audit.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const tokenWithBadHeader = (claims: Record<string, unknown>) =>
  [
    Buffer.from("not json").toString("base64url"),
    Buffer.from(JSON.stringify(claims)).toString("base64url"),
    "sig",
  ].join(".");

const cursorRow = {
  id: "event-1",
  workspaceId: "00000000-0000-0000-0000-000000000000",
  auditSeq: 42,
  ts: new Date("2026-05-10T12:34:56.789Z"),
  actorKind: "user",
  actorId: "user-1",
  action: "verify.read",
  target: { resource: "doc:1" },
  decision: "allow",
  supporting: null,
  signingKeyId: "key-1",
  prevHash: "prev",
  thisHash: "hash",
  signature: "sig",
} satisfies AuditQueryRow;

describe("audit query cursors", () => {
  it("parses server-formatted sequence cursors", () => {
    expect(parseCursor(formatCursor(cursorRow))).toEqual({ auditSeq: cursorRow.auditSeq });
  });

  it("rejects malformed cursors", () => {
    expect(parseCursor("not-a-cursor")).toBeUndefined();
    expect(parseCursor("42junk")).toBeUndefined();
  });
});

describe("admin audit routes auth hardening", () => {
  it("rejects malformed token headers as unauthorized", async () => {
    const workspaceId = "00000000-0000-0000-0000-000000000000";
    const token = tokenWithBadHeader({
      org: workspaceId,
      sub: "user-1",
      roles: ["auditor"],
    });
    const res = await app.request(
      `/v1/workspaces/${workspaceId}/audit/events`,
      { method: "GET", headers: { Authorization: `Bearer ${token}` } },
      {
        DATABASE_URL: "postgres://unused",
        MEK: "unused",
        ISSUER_BASE_URL: "https://issuer.test/acme",
        ADMIN_AUDIENCE: "pact-admin",
        AUDIT_AUDIENCE: "pact-audit",
      },
    );
    expect(res.status).toBe(401);
  });
});

run("admin audit routes", () => {
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
      slug: uniqueSlug("aud"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);

    const admin = await issueTestToken(issuer, env, {
      workspaceId: created.workspaceId,
      email: "alice@example.com",
      audience: env.ADMIN_AUDIENCE,
    });
    const audit = await issueTestToken(issuer, env, {
      workspaceId: created.workspaceId,
      email: "alice@example.com",
      audience: env.AUDIT_AUDIENCE,
    });
    const adminToken = admin.token;
    const auditToken = audit.token;

    for (const email of ["a@example.com", "b@example.com", "c@example.com"]) {
      await app.request(
        `/v1/workspaces/${created.workspaceId}/users`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            Authorization: `Bearer ${adminToken}`,
          },
          body: JSON.stringify({ email }),
        },
        {
          DATABASE_URL: env.DATABASE_URL,
          MEK: env.MEK,
          ISSUER_BASE_URL: env.ISSUER_BASE_URL,
          ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
        },
      );
    }

    return { env, created, auditToken, adminToken };
  };

  const auditEnv = (env: Record<string, unknown>) => ({
    DATABASE_URL: env.DATABASE_URL,
    MEK: env.MEK,
    ISSUER_BASE_URL: env.ISSUER_BASE_URL,
    ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    AUDIT_AUDIENCE: env.AUDIT_AUDIENCE,
  });

  it("rejects without bearer token", async () => {
    const { created, env } = await setup();
    const res = await app.request(
      `/v1/workspaces/${created.workspaceId}/audit/events`,
      { method: "GET" },
      auditEnv(env),
    );
    expect(res.status).toBe(401);
  });

  it("lists audit events with an audit-audience token", async () => {
    const { created, env, auditToken } = await setup();
    const res = await app.request(
      `/v1/workspaces/${created.workspaceId}/audit/events`,
      { method: "GET", headers: { Authorization: `Bearer ${auditToken}` } },
      auditEnv(env),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { events: Array<{ action: string }>; nextCursor: null };
    const actions = body.events.map((e) => e.action);
    expect(actions.filter((a) => a === "admin.user.created").length).toBeGreaterThanOrEqual(3);
  });

  it("lists audit events with an admin-audience token", async () => {
    const { created, env, adminToken } = await setup();
    const res = await app.request(
      `/v1/workspaces/${created.workspaceId}/audit/events`,
      { method: "GET", headers: { Authorization: `Bearer ${adminToken}` } },
      auditEnv(env),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { events: Array<{ action: string }> };
    expect(body.events.length).toBeGreaterThan(0);
  });

  it("filters events by action", async () => {
    const { created, env, auditToken } = await setup();
    const res = await app.request(
      `/v1/workspaces/${created.workspaceId}/audit/events?action=admin.user.created`,
      { method: "GET", headers: { Authorization: `Bearer ${auditToken}` } },
      auditEnv(env),
    );
    const body = (await res.json()) as { events: Array<{ action: string }> };
    expect(body.events.length).toBeGreaterThanOrEqual(3);
    expect(body.events.every((e) => e.action === "admin.user.created")).toBe(true);
  });

  it("paginates with cursor", async () => {
    const { created, env, auditToken } = await setup();
    const first = await app.request(
      `/v1/workspaces/${created.workspaceId}/audit/events?limit=2`,
      { method: "GET", headers: { Authorization: `Bearer ${auditToken}` } },
      auditEnv(env),
    );
    const firstBody = (await first.json()) as {
      events: Array<{ thisHash: string }>;
      nextCursor: string | null;
    };
    expect(firstBody.events.length).toBe(2);
    expect(firstBody.nextCursor).not.toBeNull();

    const second = await app.request(
      `/v1/workspaces/${created.workspaceId}/audit/events?limit=10&cursor=${encodeURIComponent(firstBody.nextCursor as string)}`,
      { method: "GET", headers: { Authorization: `Bearer ${auditToken}` } },
      auditEnv(env),
    );
    const secondBody = (await second.json()) as { events: Array<{ thisHash: string }> };
    const firstHashes = new Set(firstBody.events.map((e) => e.thisHash));
    expect(secondBody.events.every((e) => !firstHashes.has(e.thisHash))).toBe(true);
  });

  it("returns chain head", async () => {
    const { created, env, auditToken } = await setup();
    const res = await app.request(
      `/v1/workspaces/${created.workspaceId}/audit/chain`,
      { method: "GET", headers: { Authorization: `Bearer ${auditToken}` } },
      auditEnv(env),
    );
    const body = (await res.json()) as {
      head: { lastHash: string; lastEventId: string | null } | null;
    };
    expect(body.head).not.toBeNull();
    expect(body.head?.lastHash.length).toBeGreaterThan(0);
  });

  it("isolates events across workspaces", async () => {
    const first = await setup();
    const second = await setup();
    const res = await app.request(
      `/v1/workspaces/${first.created.workspaceId}/audit/events`,
      { method: "GET", headers: { Authorization: `Bearer ${second.auditToken}` } },
      auditEnv(first.env),
    );
    expect(res.status).toBe(401);
  });
});
